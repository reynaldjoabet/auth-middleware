package app.http.error

import cats.MonadThrow
import cats.data.{Kleisli, OptionT}
import cats.syntax.all.*
import org.http4s.{
  EntityEncoder,
  HttpRoutes,
  MessageFailure,
  Request,
  Response,
  Status
}
import org.http4s.headers.`Content-Type`
import org.http4s.circe.*

/** Last-resort error net around the route tree.
  *
  *   - A [[org.http4s.MessageFailure]] (the client sent a body we couldn't
  *     decode) becomes the http4s-chosen 4xx — never a 500.
  *   - Any other throwable is a server bug: `onError` is run (log it, returning
  *     a trace id) and the client gets an opaque `500 problem+json` carrying
  *     that id — no stack trace leaks.
  *
  * Expected domain failures should be returned as [[app.domain.error.AppError]]
  * and rendered by [[ErrorMapper]] in the route; this only catches the
  * *unexpected*. Apply once, around all routes.
  *
  * @param onError
  *   side effect (logging) for unexpected errors; returns the trace/correlation
  *   id to surface to the client (e.g. from the request's `X-Request-Id` or a
  *   freshly generated one).
  */
object ErrorMiddleware {

  def apply[F[_]: MonadThrow](
      onError: (Request[F], Throwable) => F[String]
  )(routes: HttpRoutes[F]): HttpRoutes[F] = {
    given EntityEncoder[F, ProblemDetails] = jsonEncoderOf
    Kleisli { req =>
      OptionT {
        routes(req).value.handleErrorWith {
          case mf: MessageFailure =>
            mf.toHttpResponse[F](req.httpVersion).some.pure[F]
          case t =>
            onError(req, t).map { traceId =>
              Response[F](Status.InternalServerError)
                .withEntity(
                  ProblemDetails(
                    "about:blank",
                    "Internal error",
                    500,
                    instance = Some(traceId)
                  )
                )
                .withContentType(
                  `Content-Type`(ProblemDetails.MediaTypeProblemJson)
                )
                .some
            }
        }
      }
    }
  }
}
