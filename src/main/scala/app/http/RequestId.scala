package app.http

import java.util.UUID

import cats.data.Kleisli
import cats.effect.Sync
import cats.syntax.all.*
import org.http4s.server.middleware
import org.http4s.{Header, HttpApp, Request}
import org.typelevel.ci.*

/** Correlation id for every request: taken from the client's `X-Request-ID`
  * when present, minted here when not, echoed on the response and stashed in
  * the request attributes so anything downstream (notably the 500 body from
  * [[app.http.error.ErrorMiddleware]]) can quote the same value the caller
  * sees.
  *
  * This is the id a support ticket carries. It complements, rather than
  * duplicates, the W3C trace id from [[ServerTracing]]: the trace id is
  * sampling-dependent and only meaningful inside the tracing backend, while
  * this one is always present and safe to hand to a caller.
  *
  * The value is stored under http4s's own `requestIdAttrKey`, so anything
  * expecting the stock middleware's attribute keeps working.
  *
  * ==Why an inbound id is not trusted verbatim==
  *
  * The header is attacker-controlled and its value is written to logs. http4s's
  * own middleware reuses whatever arrived, so a caller could inject newlines
  * (forging log records), or megabytes of text, into every line correlated with
  * the request. An id that is not a short, boring token is therefore discarded
  * and replaced with a freshly minted one — correlation with that particular
  * client is lost, which is strictly better than a poisoned log.
  */
object RequestId {

  val HeaderName: CIString = ci"X-Request-ID"

  /** Comfortably fits a UUID (36) or a 128-bit hex trace id (32). */
  private val MaxLength = 64

  /** Applies request-id handling to the whole app. Outermost in the stack, so
    * the id exists before any other middleware can want it.
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

  /** The id assigned to this request, if the middleware has run. */
  def find[F[_]](request: Request[F]): Option[String] =
    request.attributes.lookup(middleware.RequestId.requestIdAttrKey)

  /** Correlation only — never an authentication or authorization value, so a
    * plain random UUID is the right strength.
    */
  private def mint[F[_]: Sync]: F[String] =
    Sync[F].delay(UUID.randomUUID().toString)

  private def inboundId[F[_]](request: Request[F]): Option[String] =
    request.headers
      .get(HeaderName)
      .map(_.head.value)
      .filter(isSafe)

  /** A non-empty, bounded token of characters that cannot break a log line or a
    * header: ASCII alphanumerics plus `. _ - :` (the separators real-world ids
    * use). Deliberately not `isLetterOrDigit`, which would admit the whole
    * Unicode letter range — including scripts that render nothing like what a
    * log reader would grep for.
    */
  private def isSafe(value: String): Boolean =
    value.nonEmpty && value.length <= MaxLength && value.forall(isSafeChar)

  private def isSafeChar(character: Char): Boolean =
    (character >= 'a' && character <= 'z') ||
      (character >= 'A' && character <= 'Z') ||
      (character >= '0' && character <= '9') ||
      character == '.' || character == '_' ||
      character == '-' || character == ':'
}
