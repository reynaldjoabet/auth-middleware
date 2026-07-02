package auth

import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64

import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}
import javax.crypto.{Cipher, KeyGenerator, SecretKey}

import scala.concurrent.duration.*

import cats.effect.Sync
import cats.syntax.all.*
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
    * `SecureRandom`, base64url) and are removed on first use — the strongest
    * (strictly single-use) semantics, but per node: behind a load balancer a
    * client's retry must land on the node that minted its nonce. For multi-node
    * deployments prefer [[stateless]], which needs no shared store at all
    * (Duende's design), or supply a shared-store implementation if you need
    * single-use semantics across nodes.
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

  /** Stateless, multi-node adapter — the pattern of Duende IdentityServer's
    * `DefaultDPoPNonceValidator`: the nonce *is* an AES-GCM-encrypted server
    * timestamp, so validation is decrypt + freshness check. No nonce store, no
    * Redis: any node holding the same key can validate a nonce any other node
    * issued, and restarts lose nothing.
    *
    * Trade-off vs [[inMemory]] (which is single-use): a stateless nonce is a
    * freshness proof, not a one-time value — it stays acceptable until
    * `lifetime` elapses. Replay of a whole *proof* is still caught by the
    * verifier's jti single-use checker (per node), so what the nonce bounds is
    * the cross-node replay window: an attacker who captured a proof and plays
    * it against a *different* node has at most `lifetime` to do so. Duende
    * accepts exactly this trade (nonce validity = proof lifetime + skew); keep
    * `lifetime` as tight as your clients' round trips allow. [[BearerAuth]]
    * rotates `DPoP-Nonce` on every response, so an active client always holds a
    * fresh value and only pays a `use_dpop_nonce` round trip after idling past
    * `lifetime`.
    *
    * @param key
    *   AES key (128/192/256-bit) shared by every node — distribute via your
    *   secret manager, rotate like any other service credential. Use
    *   [[randomKey]] only for single-node or test deployments.
    * @param lifetime
    *   how long an issued nonce stays acceptable
    * @param forwardSkew
    *   tolerated clock drift for a nonce that appears to come from the future —
    *   the issuing clock is another *server* node, so keep this small (Duende's
    *   `ProofTokenNonceClockSkew` is 5 seconds, vs 25 for client-minted `iat`)
    */
  def stateless[F[_]: Sync](
      key: SecretKey,
      lifetime: FiniteDuration = 5.minutes,
      forwardSkew: FiniteDuration = 5.seconds
  ): F[DpopNonceStore[F]] =
    Sync[F].delay {
      val random = new SecureRandom()

      new DpopNonceStore[F] {
        def issue: F[DpopNonce] =
          Sync[F].realTime.flatMap { now =>
            Sync[F].delay {
              val iv = new Array[Byte](StatelessIvBytes)
              random.nextBytes(iv)
              val cipher = Cipher.getInstance(StatelessCipher)
              cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(StatelessTagBits, iv)
              )
              val ciphertext = cipher.doFinal(
                now.toSeconds.toString.getBytes(StandardCharsets.US_ASCII)
              )
              val out = new Array[Byte](iv.length + ciphertext.length)
              System.arraycopy(iv, 0, out, 0, iv.length)
              System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length)
              // base64url of 12B IV + ~26B ciphertext ≈ 51 chars: within the
              // DpopNonce refinement (base64url alphabet, ≤ 256 chars).
              DpopNonce.applyUnsafe(
                Base64.getUrlEncoder.withoutPadding.encodeToString(out)
              )
            }
          }

        def validate(presented: String): F[Status] =
          Sync[F].realTime.flatMap { now =>
            Sync[F].delay {
              // AEAD authentication makes a forged/foreign-key nonce fail the
              // doFinal tag check; anything unparsable is simply re-challenged.
              try {
                if (presented.isEmpty || presented.length > 512)
                  Status.Unacceptable
                else {
                  val in = Base64.getUrlDecoder.decode(presented)
                  if (in.length <= StatelessIvBytes) Status.Unacceptable
                  else {
                    val cipher = Cipher.getInstance(StatelessCipher)
                    cipher.init(
                      Cipher.DECRYPT_MODE,
                      key,
                      new GCMParameterSpec(
                        StatelessTagBits,
                        in,
                        0,
                        StatelessIvBytes
                      )
                    )
                    val plaintext = cipher.doFinal(
                      in,
                      StatelessIvBytes,
                      in.length - StatelessIvBytes
                    )
                    val issuedAt =
                      new String(plaintext, StandardCharsets.US_ASCII).toLong
                    val nowSeconds = now.toSeconds
                    val fresh =
                      nowSeconds - issuedAt <= lifetime.toSeconds &&
                        issuedAt - nowSeconds <= forwardSkew.toSeconds
                    if (fresh) Status.Valid else Status.Unacceptable
                  }
                }
              } catch { case _: Exception => Status.Unacceptable }
            }
          }
      }
    }

  /** A fresh 256-bit AES key for [[stateless]]. Single-node/test convenience:
    * nonces die with the process and no other node can validate them — in
    * production load a shared key ([[keyFromBytes]]) from your secret manager.
    */
  def randomKey[F[_]: Sync]: F[SecretKey] =
    Sync[F].delay {
      val generator = KeyGenerator.getInstance("AES")
      generator.init(256)
      generator.generateKey()
    }

  /** Wrap key material from a secret manager (16, 24 or 32 bytes). */
  def keyFromBytes(bytes: Array[Byte]): SecretKey = {
    require(
      Set(16, 24, 32).contains(bytes.length),
      s"AES key must be 16, 24 or 32 bytes, got ${bytes.length}"
    )
    new SecretKeySpec(bytes, "AES")
  }

  private val StatelessCipher = "AES/GCM/NoPadding"
  private val StatelessTagBits = 128
  private val StatelessIvBytes = 12
}
