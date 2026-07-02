package app.http.error

import app.domain.error.AppError

/** Maps a domain error of type `E` to its HTTP [[ProblemDetails]] body.
  *
  * One given instance per error type — each feature owns the error → status
  * decision for its *own* errors, while the wire format ([[ProblemDetails]])
  * and rendering ([[ErrorMapper.toResponse]]) stay central. Adding a new error
  * type means adding a `given`, never editing a shared match.
  */
trait ToProblemDetails[-E] {
  extension (error: E) def toProblemDetails: ProblemDetails
}

object ToProblemDetails {

  def apply[E](using thp: ToProblemDetails[E]): ToProblemDetails[E] = thp

  /** Generic cross-cutting errors. Feature-specific error types provide their
    * own instance (ideally alongside the feature).
    */
  given ToProblemDetails[AppError] with {
    extension (error: AppError) {
      def toProblemDetails: ProblemDetails = error match {
        case AppError.NotFound(resource, id) =>
          ProblemDetails(
            "about:blank",
            s"$resource not found",
            404,
            Some(s"id=$id")
          )
        case AppError.Conflict(detail) =>
          ProblemDetails("about:blank", "Conflict", 409, Some(detail))
        case AppError.Validation(detail) =>
          ProblemDetails("about:blank", "Validation failed", 422, Some(detail))
        case AppError.Forbidden(detail) =>
          ProblemDetails("about:blank", "Forbidden", 403, Some(detail))
      }
    }
  }
}
