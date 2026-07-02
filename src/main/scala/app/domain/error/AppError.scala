package app.domain.error

enum AppError derives CanEqual {
  case NotFound(resource: String, id: String)
  case Conflict(detail: String)
  case Validation(detail: String)
  case Forbidden(detail: String)
}
