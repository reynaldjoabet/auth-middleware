package app.http.error

import org.http4s.{EntityEncoder, Response, Status}
import org.http4s.headers.`Content-Type`
import org.http4s.circe.*

/** Central, uniform rendering of any domain error that has a
  * [[ToProblemDetails]] instance. The error → status decision lives in the
  * instance (per error type); this owns only the wire format
  * (`application/problem+json`) and `Response` construction.
  */
object ErrorMapper {

  def toResponse[F[_], E: ToProblemDetails](e: E): Response[F] = {
    given EntityEncoder[F, ProblemDetails] = jsonEncoderOf
    val p = e.toProblemDetails
    Response[F](Status.fromInt(p.status).getOrElse(Status.InternalServerError))
      .withEntity(p)
      .withContentType(`Content-Type`(ProblemDetails.MediaTypeProblemJson))
  }
}
