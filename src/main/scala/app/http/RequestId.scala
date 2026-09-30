package app.http

import cats.data.Kleisli
import cats.effect.Sync
import cats.syntax.all.*

import org.http4s.{Header, HttpApp, Request}
import org.http4s.server.middleware
import org.typelevel.ci.*

/**
  * Correlation id for every request: taken from the client's `X-Request-ID` when present, minted
  * here when not, echoed on the response and stashed in the request attributes so anything
  * downstream (notably the 500 body from [[app.http.error.ErrorMiddleware]]) can quote the same
  * value the caller sees.
  *
  * This is the id a support ticket carries. It complements, rather than duplicates, the W3C trace
  * id from [[ServerTracing]]: the trace id is sampling-dependent and only meaningful inside the
  * tracing backend, while this one is always present and safe to hand to a caller.
  *
  * The value is stored under http4s's own `requestIdAttrKey`, so anything expecting the stock
  * middleware's attribute keeps working.
  *
  * ==Why an inbound id is not trusted verbatim==
  *
  * The header is attacker-controlled and its value is written to logs. http4s's own middleware
  * reuses whatever arrived, so a caller could inject newlines (forging log records), or megabytes
  * of text, into every line correlated with the request. An id that is not a short, boring token is
  * therefore discarded and replaced with a freshly minted one — correlation with that particular
  * client is lost, which is strictly better than a poisoned log.
  */
object RequestId {

  val HeaderName: CIString = CIString(RequestIds.HeaderName)

  /**
    * Applies request-id handling to the whole app. Outermost in the stack, so the id exists before
    * any other middleware can want it.
    */
  def httpApp[F[_]: Sync](app: HttpApp[F]): HttpApp[F] =
    Kleisli { request =>
      inboundId(request).fold(mint[F])(_.pure[F]).flatMap { id =>
        // Rewrite the header too, so a handler reading it directly and a
        // handler reading the attribute can never disagree.
        val identified = request
          .withAttribute(middleware.RequestId.requestIdAttrKey, id)
          .putHeaders(Header.Raw(HeaderName, id))
        app(identified).map(_.putHeaders(Header.Raw(HeaderName, id)))
      }
    }

  /**
    * The id assigned to this request, if the middleware has run.
    */
  def find[F[_]](request: Request[F]): Option[String] =
    request.attributes.lookup(middleware.RequestId.requestIdAttrKey)

  // The id rules (reuse a safe inbound id, else mint one) are shared with the
  // ZIO service: see [[RequestIds]].
  private def mint[F[_]: Sync]: F[String] = Sync[F].delay(RequestIds.newId())

  private def inboundId[F[_]](request: Request[F]): Option[String] =
    request.headers.get(HeaderName).map(_.head.value).flatMap(RequestIds.accept)

}
