package auth
package dpop

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.ParseException

import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*

import cats.effect.{Resource, Sync}
import cats.syntax.all.*

import com.nimbusds.jose.{JOSEException, JWSAlgorithm}
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.dpop.verifiers.{
  AccessTokenValidationException,
  DPoPIssuer,
  DPoPProtectedResourceRequestVerifier,
  InvalidDPoPProofException
}
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import com.nimbusds.openid.connect.sdk.Nonce
import org.http4s.headers.Host
import org.http4s.Request
import org.typelevel.ci.*

/**
  * Configuration for DPoP proof validation (RFC 9449).
  *
  * @param allowedAlgorithms
  *   permitted proof signature algorithms. Must be from the EC or RSA family: the Nimbus DPoP
  *   verifier supports those only (notably NOT EdDSA). The default (ES256, PS256) matches the FAPI
  *   2.0 profile minus EdDSA.
  * @param proofMaxAge
  *   how far in the past a proof's `iat` may lie. Proofs are meant to be minted per request, so
  *   keep this tight.
  * @param clockSkew
  *   tolerated clock difference for the `iat` checks
  * @param maxProofLength
  *   hard upper bound on the proof JWT, to bound parsing work
  * @param assumeTls
  *   when the request URI carries no scheme (TLS terminated by a proxy), assume `https` when
  *   reconstructing the request URI for the `htu` check
  */
final case class DpopConfig(
    allowedAlgorithms: Set[JWSAlgorithm] = Set(JWSAlgorithm.ES256, JWSAlgorithm.PS256),
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

/**
  * Verifies DPoP proofs (RFC 9449) presented alongside DPoP-bound access tokens.
  *
  * This verifier is distinct from [[AccessTokenValidator]], which validates access tokens. Although
  * both work with JWTs, they have incompatible claims and lifecycles:
  *   - Access tokens are long-lived (hours) and issued by the authorization server
  *   - DPoP proofs are short-lived (seconds) and issued per-request by the client
  *
  * See `docs/VALIDATOR_ARCHITECTURE.md` for the full architecture.
  */
trait DpopVerifier[F[_]] {

  /**
    * Algorithms accepted for proofs — advertised in `WWW-Authenticate: DPoP algs="…"`.
    */
  def algorithms: Set[JWSAlgorithm]

  /**
    * The DPoP nonce validator when RFC 9449 §8-9 server-provided nonces are enforced.
    * [[AccessTokenAuth]] uses it to rotate the nonce: every response to a DPoP-scheme request
    * carries a fresh `DPoP-Nonce` header (§8.2), so a well-behaved client never needs a challenge
    * round trip after the first.
    */
  def dpopNonceValidator: Option[DpopNonceValidator[F]]

  /**
    * Verify that the DPoP proof is bound correctly to this request and the access token.
    *
    * Assumes the proof has already been validated as a JWT via [[DpopProofValidator]]. This method
    * checks the DPoP-specific business logic:
    *   - Key binding (proof's JWK thumbprint matches token's `cnf.jkt`)
    *   - Request binding (proof's `htm`/`htu` match this request's method/URI)
    *   - Proof freshness (proof's `iat` is recent)
    *   - Replay prevention (proof's `jti` is single-use)
    *   - Optional nonce validation (RFC 9449 §8-9 FAPI 2.0 fix)
    *
    * @param req
    *   the HTTP request carrying the DPoP header
    * @param accessToken
    *   the access token string (to compute `ath` hash for comparison)
    * @param cnfKeyThumbprint
    *   the JWK thumbprint from the access token's `cnf.jkt` claim; the proof's key must hash to
    *   exactly this value
    * @return
    *   Right(()) if proof is validly bound to this request and token; Left(AuthError) if binding
    *   fails, with diagnostics reported via AuthEvents
    */
  def verifyBinding(
      req: Request[F],
      accessToken: String,
      cnfKeyThumbprint: JwkThumbprint
  ): F[Either[AuthError, Unit]]

}

object DpopVerifier {

  private val DpopHeader = ci"DPoP"

  /**
    * `ath` claim value for an access token: base64url(SHA-256(token)).
    */
  def accessTokenHash(accessToken: String): String =
    Base64URL
      .encode(sha256(accessToken.getBytes(StandardCharsets.US_ASCII)))
      .toString

  private def sha256(bytes: Array[Byte]): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(bytes)

  /**
    * Reconstruct the request URI for the RFC 9449 `htu` comparison. Behind a TLS-terminating proxy
    * the request often has no scheme/authority of its own, so the scheme falls back to `https` (per
    * [[DpopConfig.assumeTls]]) and the authority to the `Host` header. Nimbus strips any
    * query/fragment itself.
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
    val path    = if (rawPath.isEmpty) "/" else rawPath
    URI.create(s"$scheme://$authority$path")
  }

  private val NonceClaim = "nonce"

  /**
    * Store key for a spent jti: base64url(SHA-256(thumbprint + " " + jti)). Both parts are
    * client-influenced, so hashing gives a fixed-length, injection-safe key; the thumbprint is
    * base64url (no space), so the separator keeps distinct pairs from colliding.
    */
  private[dpop] def jtiKey(thumbprint: String, jti: String): String =
    Base64URL
      .encode(sha256((thumbprint + " " + jti).getBytes(StandardCharsets.UTF_8)))
      .toString

  /**
    * Production verifier, delegating the cryptographic and claims checks to the Nimbus SDK's
    * [[DPoPProtectedResourceRequestVerifier]].
    *
    * Replay protection has two layers:
    *   - jti single-use via a [[DpopJtiStore]], checked as an effect *after* Nimbus has verified
    *     the proof (Nimbus's own synchronous checker is disabled). Defaults to a per-node in-memory
    *     store. Behind a load balancer pass a shared store (e.g. Redis) so a replayed proof is
    *     caught whichever node it lands on. A store failure fails closed as `503`.
    *   - `dpopNonceValidator`: when supplied, RS-provided nonces (RFC 9449 §8-9) are *required* on
    *     every proof. This is the FAPI 2.0 fix for DPoP Proof Replay — jti single-use alone cannot
    *     stop a network attacker who blocks the honest request, since the RS never sees the
    *     original. Leave it `None` only where mTLS binding or a lower risk tier applies.
    *
    * Acquire the verifier once at startup and reuse it across requests.
    *
    * @param jtiStore
    *   the DPoP proof `jti` single-use store. `None` (default) creates a per-node in-memory one;
    *   `Some` injects a shared store for multi-node deployments.
    */
  def default[F[_]: Sync](
      config: DpopConfig,
      events: AuthEvents[F],
      dpopNonceValidator: Option[DpopNonceValidator[F]] = None,
      jtiStore: Option[DpopJtiStore[F]] = None
  ): Resource[F, DpopVerifier[F]] =
    Resource
      .eval(jtiStore.fold(DpopJtiStore.inMemory[F])(Sync[F].pure))
      .evalMap { store =>
        Sync[F].delay {
          // Nimbus mutates the algorithm set (retainAll) during construction, so
          // it must be a mutable java.util.Set — a wrapped immutable Scala Set
          // would throw UnsupportedOperationException.
          val algs = new java.util.LinkedHashSet[JWSAlgorithm](
            config.allowedAlgorithms.asJava
          )
          // `null` single-use checker: Nimbus then skips jti tracking, which
          // `store` does effectfully once the proof has verified.
          val nimbus = new DPoPProtectedResourceRequestVerifier(
            algs,
            config.clockSkew.toSeconds,
            config.proofMaxAge.toSeconds,
            null
          )
          (nimbus, store)
        }
      }
      .map { case (nimbus, store) =>
        // A spent jti must outlive every instant at which its proof could still
        // be accepted: max age plus skew on the iat check.
        val retention = config.proofMaxAge + config.clockSkew
        // Alias: inside the anonymous class `dpopNonceValidator` is the trait member, which
        // would self-reference the parameter it is meant to expose.
        val defaultDpopNonceValidator = dpopNonceValidator
        new DpopVerifier[F] {

          val algorithms: Set[JWSAlgorithm] = config.allowedAlgorithms

          val dpopNonceValidator: Option[DpopNonceValidator[F]] =
            defaultDpopNonceValidator

          def verifyBinding(
              req: Request[F],
              accessToken: String,
              cnfKeyThumbprint: JwkThumbprint
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
                      dpopNonceValidator match {
                        case None =>
                          verifyDpopProof(
                            req,
                            accessToken,
                            cnfKeyThumbprint,
                            proof,
                            validatedNonce = null
                          )
                        case Some(validator) =>
                          val presented = nonceClaimOf(proof)
                          // A nonce store we cannot reach proves nothing: fail
                          // closed with 503, as for every other auth dependency.
                          validator.validateNonce(presented).attempt.flatMap {
                            case Left(e) =>
                              fail(
                                AuthError.ValidationUnavailable,
                                s"DPoP nonce store unavailable: ${e.getMessage}"
                              )
                            case Right(result) =>
                              (presented, result) match {
                                case (
                                      Some(value),
                                      NonceValidationResult.Valid
                                    ) =>
                                  verifyDpopProof(
                                    req,
                                    accessToken,
                                    cnfKeyThumbprint,
                                    proof,
                                    validatedNonce = new Nonce(value)
                                  )
                                case (None, NonceValidationResult.Valid) =>
                                  // defensive: no implementation may accept an
                                  // absent nonce as Valid
                                  challenge(
                                    validator,
                                    "validator accepted an absent nonce; re-challenging"
                                  )
                                case (_, NonceValidationResult.Missing) =>
                                  challenge(
                                    validator,
                                    "proof carries no nonce; issued challenge"
                                  )
                                case (_, NonceValidationResult.Invalid) =>
                                  challenge(
                                    validator,
                                    "nonce unknown, expired or already used; issued challenge"
                                  )
                              }
                          }
                      }
                  }
            }

          /**
            * Cryptographic + claims verification of the proof, delegated to Nimbus: signature
            * (against the proof's own JWK header), key binding (thumbprint vs `cnfKeyThumbprint`),
            * request binding (`htm`/`htu`), freshness (`iat`) and access token hash (`ath`). Only a
            * proof that passes all of that spends its jti in [[DpopJtiStore]].
            *
            * @param cnfKeyThumbprint
            *   the JWK thumbprint from the access token's `cnf.jkt` claim; the proof's key must
            *   hash to exactly this value
            * @param validatedNonce
            *   `null` when nonces are not enforced; otherwise a nonce this verifier has already
            *   authenticated, which Nimbus re-checks against the proof's `nonce` claim
            */
          private def verifyDpopProof(
              req: Request[F],
              accessToken: String,
              cnfKeyThumbprint: JwkThumbprint,
              proof: SignedJWT,
              validatedNonce: Nonce
          ): F[Either[AuthError, Unit]] =
            // `delay`, not `blocking`: with the jti check moved out, this is
            // pure CPU work (the proof carries its own key — no fetch).
            Sync[F]
              .delay {
                nimbus.verify(
                  req.method.name,
                  requestUri(req, config.assumeTls),
                  new DPoPIssuer(cnfKeyThumbprint.value: String),
                  proof,
                  new DPoPAccessToken(accessToken),
                  new JWKThumbprintConfirmation(
                    new Base64URL(cnfKeyThumbprint.value: String)
                  ),
                  validatedNonce
                )
              }
              .attempt
              .flatMap {
                case Right(_)                => spendJti(cnfKeyThumbprint, proof)
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

          /**
            * RFC 9449 §11.1 single use. Keyed by the proof key's thumbprint as well as the jti, so
            * one client cannot spend another's jti. A store failure fails closed as `503`: a proof
            * we cannot prove unused is not accepted.
            */
          private def spendJti(
              cnfKeyThumbprint: JwkThumbprint,
              proof: SignedJWT
          ): F[Either[AuthError, Unit]] =
            jtiOf(proof) match {
              case None =>
                fail(AuthError.InvalidDpopProof.Malformed, "proof carries no jti")
              case Some(jti) =>
                store
                  .markUsed(jtiKey(cnfKeyThumbprint.value: String, jti), retention)
                  .attempt
                  .flatMap {
                    case Right(true)  => ().asRight[AuthError].pure[F]
                    case Right(false) =>
                      fail(
                        AuthError.InvalidDpopProof.Rejected,
                        "DPoP proof jti already used: replay detected"
                      )
                    case Left(e) =>
                      fail(
                        AuthError.ValidationUnavailable,
                        s"DPoP jti store unavailable: ${e.getMessage}"
                      )
                  }
            }

          private def jtiOf(proof: SignedJWT): Option[String] =
            try Option(proof.getJWTClaimsSet.getJWTID).filter(_.nonEmpty)
            catch { case _: ParseException => None }

          /**
            * Read the proof's `nonce` claim without trusting it — it is only a lookup key into
            * [[DpopNonceValidator]], which authenticates it.
            */
          private def nonceClaimOf(proof: SignedJWT): Option[String] =
            try
              Option(proof.getJWTClaimsSet.getStringClaim(NonceClaim))
                .filter(_.nonEmpty)
            catch { case _: ParseException => None }

          /**
            * Issue a fresh nonce and answer with a `use_dpop_nonce` challenge. Reported via
            * [[AuthEvents.challengeIssued]], not `authFailed` — a challenge is routine protocol
            * flow, not a denial.
            */
          private def challenge(
              validator: DpopNonceValidator[F],
              detail: String
          ): F[Either[AuthError, Unit]] =
            validator.createNonce.attempt.flatMap {
              case Right(nonce) =>
                val err = AuthError.UseDpopNonce(nonce)
                events.challengeIssued(err, detail).as(err.asLeft)
              case Left(e) =>
                fail(
                  AuthError.ValidationUnavailable,
                  s"DPoP nonce store unavailable: ${e.getMessage}"
                )
            }

          private def fail(
              error: AuthError,
              detail: String
          ): F[Either[AuthError, Unit]] =
            events.authFailed(error, detail).as(error.asLeft)
        }
      }

}
