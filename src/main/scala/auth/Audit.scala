package auth

import java.time.Instant

import cats.effect.{Ref, Sync}
import cats.syntax.all.*
import io.github.iltotore.iron.*

/** Stable, low-cardinality code for an authentication outcome, used as the
  * audit decision. Bounded by construction — never includes claim values.
  */
private[auth] def outcomeCode(error: AuthError): String =
  error match {
    case AuthError.MissingToken                      => "missing_token"
    case _: AuthError.InvalidRequest                 => "invalid_request"
    case _: AuthError.InvalidToken                   => "invalid_token"
    case _: AuthError.InvalidDpopProof               => "invalid_dpop_proof"
    case _: AuthError.UseDpopNonce                   => "use_dpop_nonce"
    case _: AuthError.InsufficientScope              => "insufficient_scope"
    case _: AuthError.InsufficientUserAuthentication =>
      "insufficient_user_authentication"
    case AuthError.ValidationUnavailable => "validation_unavailable"
  }

/** An immutable audit record for one authentication decision. Carries only
  * redaction-safe identifiers (subject / client / token id), never token
  * material or claim values.
  */
final case class AuditRecord(
    at: Instant,
    decision: String,
    subject: Option[String],
    clientId: Option[String],
    tokenId: Option[String]
)

/** Append-only sink for audit records. Back it with durable, tamper-evident
  * storage (WORM bucket, append-only table, SIEM) for compliance.
  */
trait Audit[F[_]] {
  def record(entry: AuditRecord): F[Unit]
}

object Audit {

  /** In-memory sink, for tests and local development. Returns the sink plus a
    * reader that yields the records in insertion order.
    */
  def inMemory[F[_]: Sync]: F[(Audit[F], F[List[AuditRecord]])] =
    Ref.of[F, List[AuditRecord]](Nil).map { ref =>
      val sink = new Audit[F] {
        def record(entry: AuditRecord): F[Unit] = ref.update(entry :: _)
      }
      (sink, ref.get.map(_.reverse))
    }
}

/** Adapts an [[Audit]] sink to the [[AuthEvents]] seam: every granted or denied
  * decision is written to the audit trail, then forwarded to `underlying`.
  */
object AuditAuthEvents {

  def apply[F[_]: Sync](
      audit: Audit[F],
      underlying: AuthEvents[F]
  ): AuthEvents[F] =
    new AuthEvents[F] {

      def authSucceeded(ctx: AuthContext): F[Unit] =
        Sync[F].realTimeInstant.flatMap { now =>
          audit.record(
            AuditRecord(
              at = now,
              decision = "granted",
              subject = Some(ctx.subject.value: String),
              clientId = ctx.clientId.map(c => c.value: String),
              tokenId = ctx.tokenId.map(t => t.value: String)
            )
          )
        } *> underlying.authSucceeded(ctx)

      def authFailed(error: AuthError, internalDetail: String): F[Unit] =
        Sync[F].realTimeInstant.flatMap { now =>
          audit.record(
            AuditRecord(
              at = now,
              decision = s"denied:${outcomeCode(error)}",
              subject = None,
              clientId = None,
              tokenId = None
            )
          )
        } *> underlying.authFailed(error, internalDetail)

      // A challenge (e.g. use_dpop_nonce) is routine protocol flow, not a
      // denial — record it under its own decision prefix so failure metrics
      // and compliance reviews are not polluted with non-failures.
      override def challengeIssued(
          error: AuthError,
          internalDetail: String
      ): F[Unit] =
        Sync[F].realTimeInstant.flatMap { now =>
          audit.record(
            AuditRecord(
              at = now,
              decision = s"challenged:${outcomeCode(error)}",
              subject = None,
              clientId = None,
              tokenId = None
            )
          )
        } *> underlying.challengeIssued(error, internalDetail)
    }
}
