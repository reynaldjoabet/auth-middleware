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
  DPoPProtectedResourceRequestVerifier,
  InMemoryDPoPSingleUseChecker,
  InvalidDPoPProofException
}
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
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

/** Validates DPoP proofs (RFC 9449) presented alongside DPoP-bound access
  * tokens.
  */
trait DpopVerifier[F[_]] {

  /** Algorithms accepted for proofs — advertised in
    * `WWW-Authenticate: DPoP algs="…"`.
    */
  def algorithms: Set[JWSAlgorithm]

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

  /** Production verifier, delegating the cryptographic and claims checks to the
    * Nimbus SDK's [[DPoPProtectedResourceRequestVerifier]]. Replay protection
    * uses Nimbus's in-memory single-use checker, which is per-node only; behind
    * a load balancer, supply a shared-store `SingleUseChecker` instead.
    *
    * Returns a [[cats.effect.Resource]]: the single-use checker starts a
    * background purge timer thread that must be stopped on release (its
    * `shutdown()`), so the verifier owns a lifecycle. Acquire it once at
    * startup and reuse the value across requests.
    */
  def default[F[_]: Sync](
      config: DpopConfig,
      events: AuthEvents[F]
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
          val checker = new InMemoryDPoPSingleUseChecker(retention, retention)
          val verifier = new DPoPProtectedResourceRequestVerifier(
            algs,
            config.clockSkew.toSeconds,
            config.proofMaxAge.toSeconds,
            checker
          )
          (verifier, checker)
        }
      ) { case (_, checker) => Sync[F].delay(checker.shutdown()) }
      .map { case (nimbus, _) =>
        new DpopVerifier[F] {

          val algorithms: Set[JWSAlgorithm] = config.allowedAlgorithms

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
                  // `blocking`: signature verification is CPU work and the
                  // single-use check touches a shared map.
                  Sync[F]
                    .blocking {
                      val proof = SignedJWT.parse(proofStr)
                      nimbus.verify(
                        req.method.name,
                        requestUri(req, config.assumeTls),
                        new DPoPIssuer(expectedJkt.value: String),
                        proof,
                        new DPoPAccessToken(accessToken),
                        new JWKThumbprintConfirmation(
                          new Base64URL(expectedJkt.value: String)
                        ),
                        null // no DPoP nonce expected at this resource
                      )
                    }
                    .attempt
                    .flatMap {
                      case Right(_) => ().asRight[AuthError].pure[F]
                      case Left(e: ParseException) =>
                        fail(
                          AuthError.InvalidDpopProof.Malformed,
                          Option(e.getMessage).getOrElse("parse error")
                        )
                      // InvalidDPoPNonceException extends InvalidDPoPProofException,
                      // so this also covers the (unused) nonce path.
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
            }

          private def fail(
              error: AuthError,
              detail: String
          ): F[Either[AuthError, Unit]] =
            events.authFailed(error, detail).as(error.asLeft)
        }
      }
}
