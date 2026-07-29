package app.http

import auth.{AuthContext, TraceLogging}
import auth.given
import cats.effect.Async
import cats.syntax.all.*
import org.http4s.dsl.Http4sDsl
import org.http4s.implicits.*
import org.http4s.server.AuthMiddleware
import org.http4s.{AuthedRoutes, HttpApp, HttpRoutes, Request}
import org.slf4j.LoggerFactory
import org.typelevel.otel4s.trace.Tracer
import app.http.error.ErrorMiddleware

/** The HTTP surface: open liveness/readiness probes plus the access-token
  * protected API mounted behind [[auth.AccessTokenAuth]].
  *
  *   - `GET /health` — liveness, never touches the DB
  *   - `GET /ready` — readiness, validates a pooled connection
  *   - `GET /me` — example protected route; the [[AuthContext]] is the
  *     authenticated principal injected by the middleware
  *
  * ==Middleware order==
  *
  * {{{
  *   RequestId  ->  ServerTracing  ->  ErrorMiddleware  ->  routes
  * }}}
  *
  * [[RequestId]] is outermost so the id exists for everything inside it and is
  * echoed even on responses the layers below produce. [[ServerTracing]] sits
  * next so a span covers the whole handling, including error rendering, and can
  * record the final status. [[ErrorMiddleware]] is innermost, closest to the
  * code that can throw: it converts an unexpected throwable into an opaque
  * `problem+json` 500 quoting the request id — the id the caller already has
  * from the response header.
  */
object HttpApi {

  private val log = LoggerFactory.getLogger(getClass)

  /** @param isReady
    *   the readiness check behind `GET /ready` — normally
    *   [[app.infra.postgres.Database.ping]]. Passed in rather than derived from
    *   the pool so this layer depends on the *question*, not on HikariCP.
    */
  def httpApp[F[_]: Async: Tracer](
      isReady: F[Boolean],
      authMiddleware: AuthMiddleware[F, AuthContext]
  ): HttpApp[F] = {
    val dsl = Http4sDsl[F]
    import dsl.*

    val open = HttpRoutes.of[F] {
      case GET -> Root / "health" => Ok("ok")
      case GET -> Root / "ready"  =>
        isReady.flatMap(ready =>
          if (ready) Ok("ready") else ServiceUnavailable("db unavailable")
        )
    }

    val secured = authMiddleware(AuthedRoutes.of[AuthContext, F] {
      case GET -> Root / "me" as ctx => Ok(s"sub=${ctx.subject}")
    })

    val routes = ErrorMiddleware[F]((request, error) =>
      logUnexpected[F](request, error)
    )(open <+> secured)
    RequestId.httpApp(ServerTracing.httpApp(routes.orNotFound))
  }

  /** Logs an unexpected throwable and hands back the id quoted to the client.
    *
    * The stack trace stays here; the response gets the id and nothing else.
    * That is the whole contract: a caller can report "request 3f2a… failed" and
    * the operator can find the trace and the exception, without the error body
    * ever describing what broke.
    */
  private def logUnexpected[F[_]: Async: Tracer](
      request: Request[F],
      error: Throwable
  ): F[String] = {
    val requestId = RequestId.find(request).getOrElse("unknown")
    TraceLogging
      .withTraceContext("request_id" -> requestId) {
        log.error(
          s"Unhandled error serving ${request.method} ${request.uri.path}",
          error
        )
      }
      .as(requestId)
  }
}
