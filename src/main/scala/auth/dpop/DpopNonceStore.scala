package auth
package dpop

import scala.concurrent.duration.*

import cats.effect.Sync
import com.github.benmanes.caffeine.cache.Caffeine
import com.nimbusds.openid.connect.sdk.Nonce

/** Persistence for strictly single-use DPoP nonces: [[mint]] records a fresh
  * value, [[consume]] atomically checks-and-removes a presented one, so each
  * nonce verifies at most once anywhere the store is shared.
  *
  * This is the *storage* abstraction; the verifier consumes a
  * [[DpopNonceValidator]] — wrap a store with [[DpopNonceValidator.fromStore]].
  * Use a store-backed validator when the threat model demands one-time nonces;
  * for the store-free, multi-node alternative see
  * [[DpopNonceValidator.stateless]] (Duende's design). A distributed
  * implementation (e.g. Redis: `SET key EX ttl` to mint, `DEL` to consume — see
  * `app.infra.redis.RedisDpopNonceStore`) gives single-use semantics across
  * every node behind a load balancer.
  */
trait DpopNonceStore[F[_]] {

  /** Create and record a fresh nonce. */
  def mint: F[DpopNonce]

  /** Atomically check-and-consume a presented nonce: true iff this store (or a
    * peer sharing it) minted the value, it has not expired, and this is its
    * first use.
    */
  def consume(presented: String): F[Boolean]
}

object DpopNonceStore {

  /** In-memory, single-node store backed by Caffeine (TTL eviction, no
    * background thread). Nonces are Nimbus [[Nonce]] values (256 bits of
    * `SecureRandom`, base64url) and are removed on first use — the strongest
    * (strictly single-use) semantics, but per node: behind a load balancer a
    * client's retry must land on the node that minted its nonce.
    *
    * @param ttl
    *   how long an issued nonce stays acceptable. Must comfortably exceed a
    *   client's request round trip: the nonce handed out on one response is
    *   spent on the next request.
    * @param maxEntries
    *   cap on outstanding nonces. Every issued nonce occupies an entry until
    *   used or expired, and a caller holding a valid token can mint one per
    *   request — so this bounds worst-case memory (~150 bytes/entry; the
    *   default caps around 15 MB). Size it near `expected request rate × ttl`,
    *   not higher.
    */
  def inMemory[F[_]: Sync](
      ttl: FiniteDuration = 5.minutes,
      maxEntries: Long = 100_000L
  ): F[DpopNonceStore[F]] =
    Sync[F].delay {
      val cache =
        Caffeine
          .newBuilder()
          .expireAfterWrite(java.time.Duration.ofMillis(ttl.toMillis))
          .maximumSize(maxEntries)
          .build[String, java.lang.Boolean]()

      new DpopNonceStore[F] {
        def mint: F[DpopNonce] =
          Sync[F].delay {
            // Nimbus Nonce() = 32 bytes of SecureRandom, base64url (43 chars)
            // — same value shape the verifier consumes; refinement holds.
            val value = new Nonce().getValue
            cache.put(value, java.lang.Boolean.TRUE)
            DpopNonce.applyUnsafe(value)
          }

        def consume(presented: String): F[Boolean] =
          Sync[F].delay {
            // remove == atomic check-and-consume: single use.
            cache.asMap().remove(presented) != null
          }
      }
    }
}
