package auth

import scribe.Level
import zio.*

/**
  * Authentication outcomes to logs — the ZIO counterpart of the http4s service's
  * `AuthEvents.slf4j`, logging to scribe: successes at DEBUG (guarded, so a disabled level costs
  * one check), rejections at INFO and availability errors at ERROR, each capped at
  * `maxLinesPerSecond` by the shared [[auth.LogRateLimiter]].
  */
final class AuthEvents(maxLinesPerSecond: Int = 100) {

  private val log      = scribe.Logger("auth")
  private val rejected = new LogRateLimiter(maxLinesPerSecond)
  private val errors   = new LogRateLimiter(maxLinesPerSecond)

  def succeeded(ctx: AuthContext): UIO[Unit] =
    ZIO.succeed(if (log.includes(Level.Debug)) log.debug(s"authentication succeeded: $ctx"))

  def failed(error: AuthError, detail: String): UIO[Unit] =
    ZIO.succeed(error match {
      case AuthError.ValidationUnavailable =>
        if (log.includes(Level.Error))
          errors.tryAcquire().foreach { dropped =>
            log.error(s"token validation unavailable: $detail${droppedNote(dropped)}")
          }
      case other =>
        if (log.includes(Level.Info))
          rejected.tryAcquire().foreach { dropped =>
            log.info(s"authentication rejected ($other): $detail${droppedNote(dropped)}")
          }
    })

  private def droppedNote(dropped: Long): String =
    if (dropped == 0L) "" else s" [$dropped similar lines suppressed in the previous second]"

}
