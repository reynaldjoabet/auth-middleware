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
