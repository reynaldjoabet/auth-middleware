package auth

import cats.Applicative
import cats.effect.Sync
import org.slf4j.LoggerFactory

/** Observability hook for authentication outcomes.
  *
  * Implementations receive every decision the middleware makes, so they can
  * drive structured logs, metrics and audit trails. `internalDetail` carries
  * upstream diagnostic text (e.g. the Nimbus rejection message); it is for logs
  * only and is never included in HTTP responses. No callback ever receives raw
  * token material.
  */
trait AuthEvents[F[_]] {
  def authSucceeded(ctx: AuthContext): F[Unit]
  def authFailed(error: AuthError, internalDetail: String): F[Unit]
}

object AuthEvents {

  def noop[F[_]: Applicative]: AuthEvents[F] = new AuthEvents[F] {
    def authSucceeded(ctx: AuthContext): F[Unit] = Applicative[F].unit
    def authFailed(error: AuthError, internalDetail: String): F[Unit] =
      Applicative[F].unit
  }

  /** SLF4J-backed default: successes at DEBUG, client errors at INFO (they are
    * routine), availability problems at ERROR (they page someone).
    */
  def slf4j[F[_]: Sync]: AuthEvents[F] = new AuthEvents[F] {
    private val log = LoggerFactory.getLogger("auth")

    def authSucceeded(ctx: AuthContext): F[Unit] =
      Sync[F].delay(log.debug("authentication succeeded: {}", ctx))

    def authFailed(error: AuthError, internalDetail: String): F[Unit] =
      Sync[F].delay {
        error match {
          case AuthError.ValidationUnavailable =>
            log.error("token validation unavailable: {}", internalDetail)
          case other =>
            log.info("authentication rejected ({}): {}", other, internalDetail)
        }
      }
  }
}
