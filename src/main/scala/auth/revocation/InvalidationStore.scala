package auth
package revocation

import java.time.Instant
import java.util.concurrent.atomic.AtomicReference

import scala.concurrent.duration.*

import cats.effect.Sync
import cats.syntax.all.*

import com.github.benmanes.caffeine.cache.{Cache, Caffeine, Expiry}

/**
  * Every node's own copy of the invalidations its token service published: a [[TokenDenylist]] with
  * [[SubjectRevocations]], answered from memory. It is filled from an event stream (see
  * `app.infra.kafka.KafkaInvalidations`), so a lookup never leaves the process.
  *
  * A local copy is only as good as its feed, so it refuses to answer when it cannot vouch for
  * itself. Both cases raise, which the validator turns into a fail-closed `503`:
  *
  *   - before the first catch-up: the feed has not yet replayed the invalidations published before
  *     this node started, so a token revoked then would be accepted
  *   - when stale: the feed has not been confirmed current for `maxStaleness` (the consumer is
  *     stuck, or the broker unreachable), so recent revocations may be missing
  *
  * Entries expire on their own: a token entry once the token itself has expired, a subject entry
  * once every token issued before its cut-off has (`maxTokenLifetime` later). Memory is bounded by
  * the invalidations of one token lifetime, not by history. Both lifetimes are padded by
  * `retentionMargin`, so clock skew between the token service and this node cannot expire an entry
  * while its token is still accepted.
  */
final class InvalidationStore[F[_]] private (
    tokens: Cache[String, Instant],
    subjectCutoffs: Cache[String, Instant],
    maxStaleness: FiniteDuration,
    freshAsOf: AtomicReference[Option[Instant]]
)(using F: Sync[F])
    extends TokenDenylist[F] {

  // --- writes: the feed -----------------------------------------------------

  /**
    * Applies one invalidation. Idempotent, and order-insensitive for a subject (the latest cut-off
    * wins), so replaying the feed from any point is safe.
    */
  def apply(invalidation: TokenInvalidation): F[Unit] =
    F.delay {
      invalidation match {
        case TokenInvalidation.Token(jti, expiresAt) =>
          tokens.asMap().merge(jti, expiresAt, (a, b) => if (a.isAfter(b)) a else b): Unit
        case TokenInvalidation.Subject(subject, before, _) =>
          subjectCutoffs.asMap().merge(subject, before, (a, b) => if (a.isAfter(b)) a else b): Unit
      }
    }

  /**
    * Records that every invalidation published up to `asOf` has been applied.
    */
  def markFresh(asOf: Instant): F[Unit] =
    F.delay {
      freshAsOf.updateAndGet {
        case Some(current) if current.isAfter(asOf) => Some(current)
        case _                                      => Some(asOf)
      }: Unit
    }

  // --- reads: the validator -------------------------------------------------

  /**
    * Caught up once, and confirmed current within `maxStaleness`: what `/ready` reports.
    */
  def ready: F[Boolean] = F.delay(staleness.isEmpty)

  def isRevoked(tokenId: String): F[Boolean] =
    vouched(Option(tokens.getIfPresent(tokenId)).isDefined)

  override val subjects: Option[SubjectRevocations[F]] =
    Some(subject => vouched(Option(subjectCutoffs.getIfPresent(subject))))

  private def vouched[A](answer: => A): F[A] =
    F.delay(staleness).flatMap {
      case None         => F.delay(answer)
      case Some(reason) => F.raiseError(InvalidationStore.NotCurrent(reason))
    }

  // Why the store cannot vouch for its answers right now, if it cannot.
  private def staleness: Option[String] =
    freshAsOf.get() match {
      case None       => Some("the invalidation feed has not caught up since start")
      case Some(asOf) =>
        val age = java.time.Duration.between(asOf, Instant.now())
        Option.when(age.toNanos > maxStaleness.toNanos)(
          s"the invalidation feed was last confirmed current ${age.toSeconds} s ago"
        )
    }

}

object InvalidationStore {

  /**
    * Raised instead of answering; the validator fails the request closed with `503`.
    */
  final case class NotCurrent(reason: String) extends RuntimeException(reason)

  /**
    * @param maxTokenLifetime
    *   the longest lifetime (`exp - iat`) the token service issues; how long a subject cut-off
    *   stays relevant
    * @param maxStaleness
    *   how long the feed may go unconfirmed before lookups fail closed
    */
  def apply[F[_]: Sync](
      maxTokenLifetime: FiniteDuration,
      maxStaleness: FiniteDuration,
      retentionMargin: FiniteDuration = 5.minutes
  ): F[InvalidationStore[F]] =
    Sync[F].delay {
      val margin = retentionMargin.toNanos
      // Each entry expires at its own instant (+ margin), measured from now.
      def expiringAt(lastsUntil: Instant => Instant) =
        Caffeine
          .newBuilder()
          .expireAfter(new Expiry[String, Instant] {
            private def remaining(value: Instant): Long =
              java.time.Duration.between(Instant.now(), lastsUntil(value)).toNanos.max(0L) + margin
            def expireAfterCreate(key: String, value: Instant, now: Long): Long                = remaining(value)
            def expireAfterUpdate(key: String, value: Instant, now: Long, current: Long): Long =
              remaining(value)
            def expireAfterRead(key: String, value: Instant, now: Long, current: Long): Long =
              current
          })
          .build[String, Instant]()

      new InvalidationStore[F](
        tokens = expiringAt(identity),
        subjectCutoffs = expiringAt(_.plusNanos(maxTokenLifetime.toNanos)),
        maxStaleness = maxStaleness,
        freshAsOf = new AtomicReference(None)
      )
    }

}
