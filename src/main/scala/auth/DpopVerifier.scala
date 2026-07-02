package auth

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.ParseException

import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*

import cats.effect.{Resource, Sync}
import cats.syntax.all.*
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.{JOSEException, JWSAlgorithm}
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation
import com.nimbusds.oauth2.sdk.dpop.verifiers.{
  AccessTokenValidationException,
  DPoPIssuer,
  DPoPProofUse,
  DPoPProtectedResourceRequestVerifier,
  InMemoryDPoPSingleUseChecker,
  InvalidDPoPProofException
}
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker
import com.nimbusds.openid.connect.sdk.Nonce
import org.http4s.Request
import org.http4s.headers.Host
import org.typelevel.ci.*

/** Configuration for DPoP proof validation (RFC 9449).
  *
  * @param allowedAlgorithms
  *   permitted proof signature algorithms. Must be from the EC or RSA family:
  *   the Nimbus DPoP verifier supports those only (notably NOT EdDSA). The
  *   default (ES256, PS256) matches the FAPI 2.0 profile minus EdDSA.
  * @param proofMaxAge
  *   how far in the past a proof's `iat` may lie. Proofs are meant to be minted
  *   per request, so keep this tight.
  * @param clockSkew
  *   tolerated clock difference for the `iat` checks
  * @param maxProofLength
  *   hard upper bound on the proof JWT, to bound parsing work
  * @param assumeTls
  *   when the request URI carries no scheme (TLS terminated by a proxy), assume
  *   `https` when reconstructing the request URI for the `htu` check
  */
final case class DpopConfig(
    allowedAlgorithms: Set[JWSAlgorithm] =
      Set(JWSAlgorithm.ES256, JWSAlgorithm.PS256),
    proofMaxAge: FiniteDuration = 60.seconds,
    clockSkew: FiniteDuration = 30.seconds,
    maxProofLength: Int = 4096,
    assumeTls: Boolean = true
) {
  require(
    allowedAlgorithms.nonEmpty,
    "at least one DPoP algorithm must be allowed"
  )
  require(
    allowedAlgorithms.forall(a =>
      JWSAlgorithm.Family.EC.contains(a) || JWSAlgorithm.Family.RSA.contains(a)
    ),
    "DPoP proof algorithms must be from the EC or RSA family; the Nimbus DPoP " +
      "verifier supports neither EdDSA nor HMAC (RFC 9449 §4.2 asymmetric only)"
  )
  require(proofMaxAge > Duration.Zero, "proofMaxAge must be positive")
  require(maxProofLength > 0, "maxProofLength must be positive")
}

/** Verifies DPoP proofs (RFC 9449) presented alongside DPoP-bound access
  * tokens.
  */
trait DpopVerifier[F[_]] {

  /** Algorithms accepted for proofs — advertised in
    * `WWW-Authenticate: DPoP algs="…"`.
    */
  def algorithms: Set[JWSAlgorithm]

  /** The nonce store when RFC 9449 §8-9 server-provided nonces are enforced.
    * [[BearerAuth]] uses it to rotate the nonce: every response to a
    * DPoP-scheme request carries a fresh `DPoP-Nonce` header (§8.2), so a
    * well-behaved client never needs a challenge round trip after the first.
    */
  def nonces: Option[DpopNonceStore[F]]

  /** Verify the `DPoP` header of `req` against this request, the presented
    * access token and the token's `cnf.jkt` thumbprint (RFC 9449 §4.3).
    */
  def verify(
      req: Request[F],
      accessToken: String,
      expectedJkt: JwkThumbprint
  ): F[Either[AuthError, Unit]]
}

object DpopVerifier {

  private val DpopHeader = ci"DPoP"

  /** `ath` claim value for an access token: base64url(SHA-256(token)). */
  def accessTokenHash(accessToken: String): String =
    Base64URL
      .encode(sha256(accessToken.getBytes(StandardCharsets.US_ASCII)))
      .toString

  private def sha256(bytes: Array[Byte]): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(bytes)

  /** Reconstruct the request URI for the RFC 9449 `htu` comparison. Behind a
    * TLS-terminating proxy the request often has no scheme/authority of its
    * own, so the scheme falls back to `https` (per [[DpopConfig.assumeTls]])
    * and the authority to the `Host` header. Nimbus strips any query/fragment
    * itself.
    */
  private def requestUri[F[_]](req: Request[F], assumeTls: Boolean): URI = {
    val scheme =
      req.uri.scheme.map(_.value).getOrElse(if (assumeTls) "https" else "http")
    val authority = req.uri.authority
      .map(_.renderString)
      .orElse(
        req.headers.get[Host].map(h => h.host + h.port.fold("")(p => ":" + p))
      )
      .getOrElse("")
    val rawPath = req.uri.path.renderString
    val path = if (rawPath.isEmpty) "/" else rawPath
    URI.create(s"$scheme://$authority$path")
  }

  private val NonceClaim = "nonce"

  /** Production verifier, delegating the cryptographic and claims checks to the
    * Nimbus SDK's [[DPoPProtectedResourceRequestVerifier]].
    *
    * Replay protection has two layers:
    *   - jti single-use: defaults to Nimbus's in-memory checker, which is
    *     per-node only. Behind a load balancer pass a `singleUseChecker` backed
    *     by a shared store (e.g. Redis) so a replayed proof is caught whichever
    *     node it lands on. A supplied checker is owned by the caller; only the
    *     default in-memory one is created and shut down by this `Resource`.
    *   - `nonces`: when supplied, RS-provided nonces (RFC 9449 §8-9) are
    *     *required* on every proof. This is the FAPI 2.0 fix for DPoP Proof
    *     Replay — jti single-use alone cannot stop a network attacker who
    *     blocks the honest request, since the RS never sees the original. Leave
    *     it `None` only where mTLS binding or a lower risk tier applies.
    *
    * Returns a [[cats.effect.Resource]]: when it owns the default in-memory
    * checker, that checker starts a background purge timer thread stopped on
    * release. Acquire the verifier once at startup and reuse it across requests.
    *
    * @param singleUseChecker
    *   the DPoP proof `jti` single-use checker. `None` (default) creates and
    *   owns an in-memory, per-node checker; `Some` injects a shared-store
    *   [[com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker]] for
    *   multi-node deployments (caller-owned lifecycle).
    */
  def default[F[_]: Sync](
      config: DpopConfig,
      events: AuthEvents[F],
      nonces: Option[DpopNonceStore[F]] = None,
      singleUseChecker: Option[SingleUseChecker[DPoPProofUse]] = None
  ): Resource[F, DpopVerifier[F]] =
    Resource
      .make(
        Sync[F].delay {
          val retention = (config.proofMaxAge + config.clockSkew).toSeconds
          // Nimbus mutates the algorithm set (retainAll) during construction, so
          // it must be a mutable java.util.Set — a wrapped immutable Scala Set
          // would throw UnsupportedOperationException.
          val algs = new java.util.LinkedHashSet[JWSAlgorithm](
            config.allowedAlgorithms.asJava
          )
          // Own an in-memory checker only when the caller supplies none; a
          // supplied (e.g. shared-store) checker has a caller-managed lifecycle
          // and must not be shut down here. Only the owned one starts a purge
          // timer thread that needs stopping on release.
          val ownedInMemory: Option[InMemoryDPoPSingleUseChecker] =
            Option.when(singleUseChecker.isEmpty)(
              new InMemoryDPoPSingleUseChecker(retention, retention)
            )
          val checker: SingleUseChecker[DPoPProofUse] =
            singleUseChecker.orElse(ownedInMemory).get
          val verifier = new DPoPProtectedResourceRequestVerifier(
            algs,
            config.clockSkew.toSeconds,
            config.proofMaxAge.toSeconds,
            checker
          )
          (verifier, ownedInMemory)
        }
      ) { case (_, ownedInMemory) =>
        ownedInMemory.fold(Sync[F].unit)(c => Sync[F].delay(c.shutdown()))
      }
      .map { case (nimbus, _) =>
        // Alias: inside the anonymous class `nonces` is the trait member, which
        // would self-reference the parameter it is meant to expose.
        val defaultNonces = nonces
        new DpopVerifier[F] {

          val algorithms: Set[JWSAlgorithm] = config.allowedAlgorithms

          val nonces: Option[DpopNonceStore[F]] = defaultNonces

          def verify(
              req: Request[F],
              accessToken: String,
              expectedJkt: JwkThumbprint
          ): F[Either[AuthError, Unit]] =
            req.headers.get(DpopHeader) match {
              case None =>
                fail(
                  AuthError.InvalidDpopProof.Missing,
                  "no DPoP header on request"
                )
              case Some(values) if values.tail.nonEmpty =>
                fail(
                  AuthError.InvalidDpopProof.Malformed,
                  "multiple DPoP headers on request"
                )
              case Some(values) =>
                val proofStr = values.head.value
                if (proofStr.length > config.maxProofLength)
                  fail(
                    AuthError.InvalidDpopProof.Malformed,
                    s"proof length ${proofStr.length}"
                  )
                else
                  Sync[F].delay(SignedJWT.parse(proofStr)).attempt.flatMap {
                    case Left(e: ParseException) =>
                      fail(
                        AuthError.InvalidDpopProof.Malformed,
                        Option(e.getMessage).getOrElse("parse error")
                      )
                    case Left(other)  => Sync[F].raiseError(other)
                    case Right(proof) =>
                      // RFC 9449 §8-9: when nonces are enforced, only a proof
                      // carrying a fresh, single-use, server-issued nonce is
                      // acceptable — the FAPI 2.0 fix for DPoP Proof Replay.
                      nonces match {
                        case None =>
                          runNimbus(req, accessToken, expectedJkt, proof, null)
                        case Some(store) =>
                          nonceClaimOf(proof) match {
                            case None            => challenge(store)
                            case Some(presented) =>
                              store.validate(presented).flatMap {
                                case DpopNonceStore.Status.Valid =>
                                  runNimbus(
                                    req,
                                    accessToken,
                                    expectedJkt,
                                    proof,
                                    new Nonce(presented)
                                  )
                                case DpopNonceStore.Status.Unacceptable =>
                                  challenge(store)
                              }
                          }
                      }
                  }
            }

          /** Run the Nimbus cryptographic + claims verification.
            * `expectedNonce` is `null` when nonces are not enforced; otherwise
            * the already-validated value Nimbus re-checks against the proof.
            */
          private def runNimbus(
              req: Request[F],
              accessToken: String,
              expectedJkt: JwkThumbprint,
              proof: SignedJWT,
              expectedNonce: Nonce
          ): F[Either[AuthError, Unit]] =
            // `blocking`: signature verification is CPU work and the single-use
            // check touches a shared map.
            Sync[F]
              .blocking {
                nimbus.verify(
                  req.method.name,
                  requestUri(req, config.assumeTls),
                  new DPoPIssuer(expectedJkt.value: String),
                  proof,
                  new DPoPAccessToken(accessToken),
                  new JWKThumbprintConfirmation(
                    new Base64URL(expectedJkt.value: String)
                  ),
                  expectedNonce
                )
              }
              .attempt
              .flatMap {
                case Right(_)                => ().asRight[AuthError].pure[F]
                case Left(e: ParseException) =>
                  fail(
                    AuthError.InvalidDpopProof.Malformed,
                    Option(e.getMessage).getOrElse("parse error")
                  )
                // InvalidDPoPNonceException extends InvalidDPoPProofException.
                case Left(e: InvalidDPoPProofException) =>
                  fail(
                    AuthError.InvalidDpopProof.Rejected,
                    Option(e.getMessage).getOrElse("invalid DPoP proof")
                  )
                case Left(e: AccessTokenValidationException) =>
                  fail(
                    AuthError.InvalidDpopProof.Rejected,
                    Option(e.getMessage)
                      .getOrElse("access token binding failed")
                  )
                case Left(e: JOSEException) =>
                  fail(
                    AuthError.InvalidDpopProof.Rejected,
                    Option(e.getMessage).getOrElse("JOSE error")
                  )
                case Left(other) => Sync[F].raiseError(other)
              }

          /** Read the proof's `nonce` claim without trusting it — it is only a
            * lookup key into [[DpopNonceStore]], which authenticates it.
            */
          private def nonceClaimOf(proof: SignedJWT): Option[String] =
            try
              Option(proof.getJWTClaimsSet.getStringClaim(NonceClaim))
                .filter(_.nonEmpty)
            catch { case _: ParseException => None }

          /** Issue a fresh nonce and answer with a `use_dpop_nonce` challenge.
            * Reported via [[AuthEvents.challengeIssued]], not `authFailed` — a
            * challenge is routine protocol flow, not a denial.
            */
          private def challenge(
              store: DpopNonceStore[F]
          ): F[Either[AuthError, Unit]] =
            store.issue.flatMap { nonce =>
              val err = AuthError.UseDpopNonce(nonce)
              events
                .challengeIssued(err, "DPoP nonce required; issued challenge")
                .as(err.asLeft)
            }

          private def fail(
              error: AuthError,
              detail: String
          ): F[Either[AuthError, Unit]] =
            events.authFailed(error, detail).as(error.asLeft)
        }
      }
}
