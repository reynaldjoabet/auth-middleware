package auth

import cats.syntax.all.*
import cats.{Applicative, Monad}
import cats.effect.Sync
import org.slf4j.LoggerFactory
import org.typelevel.otel4s.Attribute
import org.typelevel.otel4s.metrics.Meter

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

  /** A protocol challenge was issued — e.g. `use_dpop_nonce` (RFC 9449 §8): the
    * client is being told *how* to authenticate, not being denied. Routine
    * traffic, so it must not be counted as a failure in metrics or audit
    * trails. Defaults to [[authFailed]] for implementations written before this
    * hook existed.
    */
  def challengeIssued(error: AuthError, internalDetail: String): F[Unit] =
    authFailed(error, internalDetail)
}

object AuthEvents {

  def noop[F[_]: Applicative]: AuthEvents[F] = new AuthEvents[F] {
    def authSucceeded(ctx: AuthContext): F[Unit] = Applicative[F].unit
    def authFailed(error: AuthError, internalDetail: String): F[Unit] =
      Applicative[F].unit
    override def challengeIssued(
        error: AuthError,
        internalDetail: String
    ): F[Unit] = Applicative[F].unit
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

    // DEBUG, and only the stable code: a challenge is routine protocol flow,
    // and the full error would render payload (e.g. the DPoP nonce) into logs.
    override def challengeIssued(
        error: AuthError,
        internalDetail: String
    ): F[Unit] =
      Sync[F].delay(
        log.debug(
          "challenge issued ({}): {}",
          outcomeCode(error),
          internalDetail
        )
      )
  }

  /** OpenTelemetry metrics sink — the port of Duende's `Telemetry` counters.
    * Emits `auth.decisions` (attribute `auth.outcome`: `success` or the stable
    * failure code) and `auth.challenges` separately: a challenge such as
    * `use_dpop_nonce` is routine protocol flow and must never inflate failure
    * rates or trip alerts. Only bounded, low-cardinality codes become
    * attributes — never claim values or internal detail.
    */
  def otel[F[_]: Monad](meter: Meter[F]): F[AuthEvents[F]] =
    for {
      decisions <- meter
        .counter[Long]("auth.decisions")
        .withDescription("Authentication decisions, by stable outcome code")
        .create
      challenges <- meter
        .counter[Long]("auth.challenges")
        .withDescription(
          "Protocol challenges issued (routine flow, not failures)"
        )
        .create
    } yield new AuthEvents[F] {
      def authSucceeded(ctx: AuthContext): F[Unit] =
        decisions.inc(Attribute("auth.outcome", "success"))

      def authFailed(error: AuthError, internalDetail: String): F[Unit] =
        decisions.inc(Attribute("auth.outcome", outcomeCode(error)))

      override def challengeIssued(
          error: AuthError,
          internalDetail: String
      ): F[Unit] =
        challenges.inc(Attribute("auth.outcome", outcomeCode(error)))
    }

  /** Fan out every decision to several sinks — e.g. `combine(slf4j, otelSink)`
    * for structured logs plus metrics.
    */
  def combine[F[_]: Applicative](sinks: AuthEvents[F]*): AuthEvents[F] =
    new AuthEvents[F] {
      def authSucceeded(ctx: AuthContext): F[Unit] =
        sinks.toList.traverse_(_.authSucceeded(ctx))

      def authFailed(error: AuthError, internalDetail: String): F[Unit] =
        sinks.toList.traverse_(_.authFailed(error, internalDetail))

      override def challengeIssued(
          error: AuthError,
          internalDetail: String
      ): F[Unit] =
        sinks.toList.traverse_(_.challengeIssued(error, internalDetail))
    }
}
