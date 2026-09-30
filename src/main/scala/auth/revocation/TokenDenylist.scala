package auth
package revocation

import scala.concurrent.duration.FiniteDuration

import cats.effect.Sync
import cats.syntax.all.*
import cats.Applicative

import com.github.benmanes.caffeine.cache.Caffeine

/**
  * Revocation check, consulted after a token has passed cryptographic and claims validation. Back
  * this with Redis or a database keyed by `jti` to support immediate token revocation (account
  * compromise, employee offboarding, fraud holds) without waiting for the token to expire.
  *
  * Keep `jti` in [[AccessTokenConfig.requiredClaims]] (the default does) so tokens cannot dodge the
  * check by omitting it.
  *
  * A failure (raised error, including a timeout) means "cannot tell": the validator fails closed
  * with `503`, never treating an unreachable store as "not revoked".
  */
trait TokenDenylist[F[_]] {

  def isRevoked(tokenId: String): F[Boolean]

  /**
    * Subject-wide revocations, if this denylist has them: every token of a subject issued before a
    * cut-off is rejected. `None` (the default) means this denylist only knows single tokens.
    */
  def subjects: Option[SubjectRevocations[F]] = None

}

/**
  * "Every token `subject` was issued before `t` is revoked" — one entry covers all of a user's
  * outstanding tokens, whether or not anyone knows their `jti`s. What a role change, a password
  * reset or "sign out everywhere" needs: the user signs in again and gets a token reflecting the
  * change.
  */
trait SubjectRevocations[F[_]] {

  /**
    * The latest cut-off for `subject`, if any.
    */
  def revokedBefore(subject: String): F[Option[java.time.Instant]]

}

object SubjectRevocations {

  /**
    * Whether a token issued at `issuedAt` falls under the cut-off `before`.
    *
    * `iat` has whole-second precision, so a token issued in the same second as the cut-off cannot
    * be placed before or after it; it counts as revoked. At worst a token minted just after the
    * change is rejected once and the client fetches another. A token without `iat` is revoked too:
    * its age cannot be shown.
    */
  def covers(before: java.time.Instant, issuedAt: Option[java.time.Instant]): Boolean =
    issuedAt.forall(iat => !iat.isAfter(before.truncatedTo(java.time.temporal.ChronoUnit.SECONDS)))

}

object TokenDenylist {

  def none[F[_]: Applicative]: TokenDenylist[F] = new TokenDenylist[F] {
    def isRevoked(tokenId: String): F[Boolean] = Applicative[F].pure(false)
  }

  /**
    * Per-node read-through cache in front of a shared denylist.
    *
    * Without it every authenticated request costs one store round trip, so the store's throughput
    * caps the fleet's. With it a node asks about a given `jti` at most once per `ttl`, turning
    * store load from "requests per second" into "distinct active tokens per `ttl`".
    *
    * The price is bounded revocation latency: a token revoked just after a node cached "not
    * revoked" is still accepted on that node for up to `ttl`. Keep `ttl` small (around a second)
    * where revocation must be near-immediate. Errors are never cached, so a store blip does not
    * outlive itself.
    */
  def cached[F[_]: Sync](
      underlying: TokenDenylist[F],
      ttl: FiniteDuration,
      maxEntries: Long
  ): F[TokenDenylist[F]] =
    Sync[F].delay {
      val answers = Caffeine
        .newBuilder()
        .expireAfterWrite(java.time.Duration.ofNanos(ttl.toNanos))
        .maximumSize(maxEntries)
        .build[String, java.lang.Boolean]()

      new TokenDenylist[F] {
        // Not cached: subject cut-offs come from a local store (see
        // KafkaInvalidations), where a lookup is a map read.
        override def subjects: Option[SubjectRevocations[F]] = underlying.subjects

        def isRevoked(tokenId: String): F[Boolean] =
          Sync[F].delay(Option(answers.getIfPresent(tokenId))).flatMap {
            case Some(revoked) => (revoked: Boolean).pure[F]
            case None          =>
              underlying
                .isRevoked(tokenId)
                .flatTap(revoked => Sync[F].delay(answers.put(tokenId, revoked)))
          }
      }
    }

}
