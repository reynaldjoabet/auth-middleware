package app.http.error

import io.circe.Encoder
import org.http4s.MediaType

/** RFC 7807 problem-details error body (`application/problem+json`). The wire
  * shape of a failure — lives in the http layer, never in `domain`.
  */
final case class ProblemDetails(
    tpe: String,
    title: String,
    status: Int,
    detail: Option[String] = None,
    instance: Option[String] = None,
    code: Option[String] = None
)

object ProblemDetails {

  /** RFC 7807 media type for problem responses. Uses http4s's MimeDB-predefined
    * constant — resolved at compile time, no runtime parse, no `unsafeParse`
    * throw, and it carries the registered metadata (binary, compressible).
    */
  val MediaTypeProblemJson: MediaType = MediaType.application.`problem+json`

  // `tpe` is serialized as the RFC 7807 `type` member.
  given Encoder[ProblemDetails] =
    Encoder.forProduct6(
      "type",
      "title",
      "status",
      "detail",
      "instance",
      "code"
    )(p => (p.tpe, p.title, p.status, p.detail, p.instance, p.code))
}
