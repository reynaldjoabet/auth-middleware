package auth

import java.util.concurrent.atomic.AtomicInteger

import app.http.RequestIds
import zio.*
import zio.http.*

/**
  * The HTTP surface on zio-http, mirroring `app.http.HttpApi` + `app.http.Server`: open `/health`
  * and `/ready`, the protected `/me`, and the same outer layers in the same order —
  *
  * {{{
  *   load shedding  ->  request timeout  ->  request id  ->  routes (+ auth aspect)
  * }}}
  *
  * Differences from the http4s service, none on the request path being compared: no OpenTelemetry,
  * `/ready` does not ping Postgres, and there is no readiness drain on shutdown.
  */
object HttpApi {

  val ProbePaths: Set[String] = Set("/health", "/ready")

  def routes(
      validator: AccessTokenValidator,
      events: AuthEvents,
      http: HttpSettings
  ): Routes[Any, Response] = {
    val open = Routes(
      Method.GET / "health" -> handler(Response.text("ok")),
      Method.GET / "ready"  -> handler(Response.text("ready"))
    )
    val secured = Routes(
      Method.GET / "me" -> handler { (_: Request) =>
        withContext((ctx: AuthContext) => Response.text(s"sub=${ctx.subject}"))
      }
    ) @@ AccessTokenAuth.aspect(validator, events)

    val inFlight = new AtomicInteger(0)
    (open ++ secured).transform(h =>
      loadShedding(inFlight, http.maxInFlight)(
        timeout(http.requestTimeout)(requestId(h))
      )
    )
  }

  type H = Handler[Any, Response, Request, Response]

  // Each wrapper calls the handler it wraps, which runs in the request's scope;
  // `Handler.scoped` hands that requirement back to zio-http, which provides it.

  /**
    * Reuse a safe inbound `X-Request-ID` or mint one (the shared [[app.http.RequestIds]] rules),
    * set it on the request and echo it on the response.
    */
  def requestId(h: H): H =
    Handler.scoped[Any](Handler.fromFunctionZIO[Request] { request =>
      ZIO.suspendSucceed {
        val id = request.headers
          .rawHeaders(RequestIds.HeaderName)
          .headOption
          .flatMap(RequestIds.accept)
          .getOrElse(RequestIds.newId())
        val identified = request.updateHeaders(
          _.removeHeader(RequestIds.HeaderName)
            .addHeader(RequestIds.HeaderName, id)
        )
        h(identified)
          .map(_.addHeader(RequestIds.HeaderName, id))
          .mapError(_.addHeader(RequestIds.HeaderName, id))
      }
    })

  /**
    * Past `limit`, the client gets `503` and the handler is interrupted.
    */
  def timeout(limit: Duration)(h: H): H =
    Handler.scoped[Any](Handler.fromFunctionZIO[Request] { request =>
      h(request).timeout(limit).map(_.getOrElse(Response.status(Status.ServiceUnavailable)))
    })

  /**
    * At most `max` requests in flight; the excess gets an immediate `503` + `Retry-After: 1`. Probe
    * paths are exempt (see `app.http.LoadShedding`).
    */
  def loadShedding(inFlight: AtomicInteger, max: Int)(h: H): H =
    Handler.scoped[Any](Handler.fromFunctionZIO[Request] { request =>
      if (ProbePaths.contains(request.path.encode)) h(request)
      else
        ZIO.suspendSucceed {
          if (inFlight.incrementAndGet() > max) {
            inFlight.decrementAndGet()
            ZIO.succeed(
              Response(
                status = Status.ServiceUnavailable,
                headers = Headers("Retry-After" -> "1", "Cache-Control" -> "no-store")
              )
            )
          } else h(request).ensuring(ZIO.succeed(inFlight.decrementAndGet()))
        }
    })

}
