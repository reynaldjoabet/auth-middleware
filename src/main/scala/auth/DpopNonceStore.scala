package auth

import scala.concurrent.duration.*

import cats.effect.Sync
import com.github.benmanes.caffeine.cache.Caffeine
import com.nimbusds.openid.connect.sdk.Nonce

/** Resource-server-provided DPoP nonces (RFC 9449 §8-9).
  *
  * When a [[DpopVerifier]] is given one of these, it refuses a proof that does
  * not carry a fresh, server-minted `nonce` claim: the client is told to retry
  * with a `DPoP-Nonce` the RS just issued. This is the fix the FAPI 2.0 formal
  * analysis mandates for the DPoP Proof Replay attack — without it a leaked (or
  * blocked-and-substituted) resource request can be replayed, because per-node
  * jti single-use detection never sees the honest request. See
  * [[SenderConstraintPolicy]] for why mTLS binding is not vulnerable here.
  *
  * A nonce is single-use: [[validate]] consumes it, so a replayed proof carries
  * a nonce that no longer verifies and is re-challenged.
  */
trait DpopNonceStore[F[_]] {

  /** Mint a fresh nonce to hand to the client in a `DPoP-Nonce` header. */
  def issue: F[DpopNonce]

  /** Consume a client-presented nonce. [[DpopNonceStore.Status.Valid]] iff it
    * is one this server issued, still within its lifetime, and not yet used.
    */
  def validate(presented: String): F[DpopNonceStore.Status]
}

object DpopNonceStore {

  enum Status derives CanEqual {
    case Valid
    case Unacceptable // unknown, expired or already used → re-challenge
  }

  /** In-memory, single-node adapter backed by Caffeine (TTL eviction, no
    * background thread). Nonces are Nimbus [[Nonce]] values (256 bits of
    * `SecureRandom`, base64url) and are removed on first use. Behind a load
    * balancer each node only accepts nonces it minted; supply a shared-store
    * implementation (e.g. Redis) so a client's retry can land on any node.
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
        def issue: F[DpopNonce] =
          Sync[F].delay {
            // Nimbus Nonce() = 32 bytes of SecureRandom, base64url (43 chars)
            // — same value shape the verifier consumes; refinement holds.
            val value = new Nonce().getValue
            cache.put(value, java.lang.Boolean.TRUE)
            DpopNonce.applyUnsafe(value)
          }

        def validate(presented: String): F[Status] =
          Sync[F].delay {
            // remove == atomic check-and-consume: single use.
            if (cache.asMap().remove(presented) != null) Status.Valid
            else Status.Unacceptable
          }
      }
    }
}
