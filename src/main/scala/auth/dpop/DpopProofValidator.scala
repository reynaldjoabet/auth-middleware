package auth.dpop

import java.security.Key
import java.text.ParseException

import scala.jdk.CollectionConverters.*

import cats.effect.Sync
import cats.syntax.all.*
import com.nimbusds.jose.{JOSEException, JOSEObjectType, JWSHeader}
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.jwk.{KeyConverter, KeyType}
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.{
  BadJOSEException,
  DefaultJOSEObjectTypeVerifier,
  JWSKeySelector,
  JWSVerificationKeySelector,
  SecurityContext
}
import com.nimbusds.jwt.proc.{DefaultJWTClaimsVerifier, DefaultJWTProcessor}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}

import auth.{AuthError, AuthEvents}

/** Validates a DPoP proof (RFC 9449) as a standalone JWT: structure, `typ`
  * header, signature, claim presence/format, and `iat` freshness. Unlike an
  * access token, a proof has no issuer, audience or subject, so successful
  * validation yields the proof's raw [[JWTClaimsSet]] rather than an
  * [[auth.AuthContext AuthContext]].
  *
  * This validator does NOT verify:
  *   - Key binding to an access token's `cnf.jkt`
  *   - Request binding (`htm`/`htu` match to a specific request)
  *   - Access token hash (`ath` value against a concrete token)
  *   - Replay prevention (`jti` single-use)
  *   - Nonce validation (RFC 9449 §8-9)
  *
  * All of those are [[DpopVerifier.verifyBinding]]'s job, and Nimbus's request
  * verifier re-checks the signature and claims there as well, so the production
  * request path does not need this validator. It exists for flows that must
  * judge a proof away from a resource request — e.g. an authorization-server
  * token endpoint or diagnostics tooling.
  */
trait DpopProofValidator[F[_]] {

  /** Validate a compact-serialized DPoP proof JWT. Returns the proof's claims
    * on the right; a redaction-safe [[AuthError]] on the left, with internal
    * diagnostics reported via [[auth.AuthEvents AuthEvents]].
    */
  def validate(proof: String): F[Either[AuthError, JWTClaimsSet]]
}

object DpopProofValidator {

  /** JOSE `typ` for DPoP proof JWTs (RFC 9449 §4.1). */
  val JoseTypeDpopJwt: JOSEObjectType = new JOSEObjectType("dpop+jwt")

  /** Production factory: verifies the proof's signature with the public key
    * carried in its own `jwk` header, as RFC 9449 §4.2 prescribes — a proof is
    * self-signed by the client's key, there is no external JWKS to consult. The
    * header key is only trusted here to be *self-consistent*; proving it is the
    * key the access token was bound to is [[DpopVerifier.verifyBinding]]'s job
    * (`cnf.jkt` comparison).
    */
  def default[F[_]: Sync](
      config: DpopConfig,
      events: AuthEvents[F]
  ): DpopProofValidator[F] =
    new Impl[F](
      config,
      new ProofHeaderJwkSelector(config.allowedAlgorithms),
      events
    )

  /** Verify proofs only against a caller-supplied key source instead of the
    * proof's own `jwk` header — for key pinning and tests.
    */
  def withKeySource[F[_]: Sync](
      config: DpopConfig,
      keySource: JWKSource[SecurityContext],
      events: AuthEvents[F]
  ): DpopProofValidator[F] =
    new Impl[F](
      config,
      new JWSVerificationKeySelector[SecurityContext](
        config.allowedAlgorithms.asJava,
        keySource
      ),
      events
    )

  /** Select the verification key from the proof's own `jwk` header. Returning
    * no key makes the processor reject the proof, so each guard below is a
    * rejection rule:
    *   - `alg` must be allowlisted (asymmetric only — [[DpopConfig]] forbids
    *     HMAC, where the header key would be the secret itself)
    *   - the header must carry a JWK
    *   - the JWK must be public-only; RFC 9449 §4.2 forbids private material
    *   - the JWK's key type must match the `alg` family (an EC key cannot back
    *     an RSA signature)
    */
  private final class ProofHeaderJwkSelector(
      allowedAlgorithms: Set[com.nimbusds.jose.JWSAlgorithm]
  ) extends JWSKeySelector[SecurityContext] {

    def selectJWSKeys(
        header: JWSHeader,
        context: SecurityContext
    ): java.util.List[Key] = {
      val jwk = header.getJWK
      val acceptable =
        allowedAlgorithms.contains(header.getAlgorithm) &&
          jwk != null &&
          !jwk.isPrivate &&
          KeyType.forAlgorithm(header.getAlgorithm).equals(jwk.getKeyType)
      if (acceptable) KeyConverter.toJavaKeys(java.util.List.of(jwk))
      else java.util.Collections.emptyList[Key]()
    }
  }

  private final class Impl[F[_]: Sync](
      config: DpopConfig,
      keySelector: JWSKeySelector[SecurityContext],
      events: AuthEvents[F]
  ) extends DpopProofValidator[F] {

    private val processor: DefaultJWTProcessor[SecurityContext] = {
      val p = new DefaultJWTProcessor[SecurityContext]()
      // DPoP proofs must have typ: dpop+jwt (RFC 9449 §4.1)
      p.setJWSTypeVerifier(
        new DefaultJOSEObjectTypeVerifier[SecurityContext](JoseTypeDpopJwt)
      )
      p.setJWSKeySelector(keySelector)
      // DPoP proofs require: iat (freshness), jti (replay prevention).
      // ath, htm, htu values are checked against the request by
      // DpopVerifier.verifyBinding, not here.
      val claimsVerifier = new DefaultJWTClaimsVerifier[SecurityContext](
        null, // no audience for DPoP
        null, // no issuer for DPoP
        Set("iat", "jti").asJava, // required claims
        null // no prohibited claims
      )
      claimsVerifier.setMaxClockSkew(config.clockSkew.toSeconds.toInt)
      p.setJWTClaimsSetVerifier(claimsVerifier)
      p
    }

    def validate(proof: String): F[Either[AuthError, JWTClaimsSet]] =
      if (proof.length > config.maxProofLength)
        reject(
          AuthError.InvalidDpopProof.Malformed,
          s"proof length ${proof.length}"
        )
      else
        Sync[F]
          .blocking(processor.process(SignedJWT.parse(proof), null))
          .attempt
          .flatMap {
            case Right(claims) =>
              checkFreshness(claims).flatMap {
                case Right(_)       => checkProofClaimFormats(claims)
                case left @ Left(_) => left.pure[F]
              }
            case Left(e: ParseException) =>
              reject(
                AuthError.InvalidDpopProof.Malformed,
                Option(e.getMessage).getOrElse("parse error")
              )
            case Left(e: BadJOSEException) =>
              reject(
                AuthError.InvalidDpopProof.Rejected,
                Option(e.getMessage).getOrElse("JOSE error")
              )
            case Left(e: KeySourceException) =>
              reject(
                AuthError.InvalidDpopProof.Rejected,
                Option(e.getMessage).getOrElse("key source error")
              )
            case Left(e: JOSEException) =>
              reject(
                AuthError.InvalidDpopProof.Rejected,
                Option(e.getMessage).getOrElse("JOSE error")
              )
            case Left(other) => Sync[F].raiseError(other)
          }

    /** A proof has no `exp`; its lifetime is `iat` +
      * [[DpopConfig.proofMaxAge]]. Reject proofs older than that window
      * (expired) or with `iat` further in the future than the clock skew allows
      * (not yet valid).
      */
    private def checkFreshness(
        claims: JWTClaimsSet
    ): F[Either[AuthError, JWTClaimsSet]] =
      Sync[F].realTimeInstant.flatMap { now =>
        // iat presence is enforced by the claims verifier above
        val iat = claims.getIssueTime.toInstant
        val oldestAcceptable =
          now.minusSeconds((config.proofMaxAge + config.clockSkew).toSeconds)
        val newestAcceptable = now.plusSeconds(config.clockSkew.toSeconds)
        if (iat.isBefore(oldestAcceptable))
          reject(
            AuthError.InvalidDpopProof.Rejected,
            "proof expired (stale iat)"
          )
        else if (iat.isAfter(newestAcceptable))
          reject(
            AuthError.InvalidDpopProof.Rejected,
            "proof not yet valid (iat in the future)"
          )
        else claims.asRight[AuthError].pure[F]
      }

    /** Require the DPoP-specific claims to be present and string-typed. Their
      * values are only meaningful against a concrete request/token, so checking
      * them is [[DpopVerifier.verifyBinding]]'s job.
      */
    private def checkProofClaimFormats(
        claims: JWTClaimsSet
    ): F[Either[AuthError, JWTClaimsSet]] = {
      val proofErrors = List("ath", "htm", "htu").flatMap { name =>
        Option(claims.getClaim(name)).filter(_.isInstanceOf[String]) match {
          case Some(_) => Nil
          case None    => List(s"$name claim missing or not a string")
        }
      }
      if (proofErrors.nonEmpty)
        reject(
          AuthError.InvalidDpopProof.Rejected,
          proofErrors.mkString("; ")
        )
      else claims.asRight[AuthError].pure[F]
    }

    private def reject(
        error: AuthError,
        detail: String
    ): F[Either[AuthError, JWTClaimsSet]] =
      events.authFailed(error, Option(detail).getOrElse("")).as(error.asLeft)
  }
}
