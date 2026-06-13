package auth

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.ParseException
import java.time.Instant

import scala.concurrent.duration.*
import auth.given
import cats.effect.{Clock, Ref, Sync}
import cats.syntax.all.*
import com.nimbusds.jose.crypto.{ECDSAVerifier, Ed25519Verifier, RSASSAVerifier}
import com.nimbusds.jose.jwk.{ECKey, JWK, OctetKeyPair, RSAKey}
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.{
  JOSEException,
  JOSEObjectType,
  JWSAlgorithm,
  JWSVerifier
}
import com.nimbusds.jwt.SignedJWT
import org.http4s.headers.Host
import org.http4s.{Request, Uri}
import org.typelevel.ci.*

/** Configuration for DPoP proof validation (RFC 9449).
  *
  * @param allowedAlgorithms
  *   permitted proof signature algorithms. The default set (ES256, PS256,
  *   EdDSA) matches the FAPI 2.0 security profile; RSASSA-PKCS1 (RS256) is
  *   deliberately excluded.
  * @param proofMaxAge
  *   how far in the past a proof's `iat` may lie. Proofs are meant to be minted
  *   per request, so keep this tight.
  * @param clockSkew
  *   tolerated clock difference for the `iat` checks
  * @param maxProofLength
  *   hard upper bound on the proof JWT, to bound parsing work
  * @param maxJtiLength
  *   hard upper bound on the proof's `jti`, to bound replay-cache entries
  * @param assumeTls
  *   when the request URI carries no scheme (TLS terminated by a proxy), assume
  *   `https` when matching the proof's `htu` claim
  */
final case class DpopConfig(
    allowedAlgorithms: Set[JWSAlgorithm] =
      Set(JWSAlgorithm.ES256, JWSAlgorithm.PS256, JWSAlgorithm.EdDSA),
    proofMaxAge: FiniteDuration = 60.seconds,
    clockSkew: FiniteDuration = 30.seconds,
    maxProofLength: Int = 4096,
    maxJtiLength: Int = 256,
    assumeTls: Boolean = true
) {
  require(
    allowedAlgorithms.nonEmpty,
    "at least one DPoP algorithm must be allowed"
  )
  require(
    !allowedAlgorithms.exists(JWSAlgorithm.Family.HMAC_SHA.contains),
    "DPoP proofs must use asymmetric algorithms (RFC 9449 §4.2)"
  )
  require(proofMaxAge > Duration.Zero, "proofMaxAge must be positive")
  require(maxProofLength > 0, "maxProofLength must be positive")
}

/** Replay protection for DPoP proof `jti` values (RFC 9449 §11.1).
  *
  * The in-memory implementation is per-node only; behind a load balancer, back
  * this with a shared store (e.g. Redis `SET key 1 NX EX ttl`) so a captured
  * proof cannot be replayed against a different node.
  */
trait DpopReplayCache[F[_]] {

  /** Record `jti` if it has not been seen before. Returns `true` if newly
    * recorded, `false` if it was already present (i.e. the proof is a replay).
    * Implementations must be atomic check-and-set; a get-then-put race would
    * admit replays.
    */
  def register(jti: String, expiresAt: Instant): F[Boolean]
}

object DpopReplayCache {

  /** Bounded in-memory cache. When full, expired entries are pruned; if it is
    * still full after pruning, registration fails closed (the proof is
    * rejected) rather than silently dropping replay protection.
    */
  def inMemory[F[_]: Sync](maxEntries: Int = 100_000): F[DpopReplayCache[F]] =
    Ref.of[F, Map[String, Instant]](Map.empty).map { ref =>
      new DpopReplayCache[F] {
        def register(jti: String, expiresAt: Instant): F[Boolean] =
          Clock[F].realTimeInstant.flatMap { now =>
            ref.modify { entries =>
              val pruned =
                if (entries.size >= maxEntries) entries.filter {
                  case (_, exp) => exp.isAfter(now)
                }
                else entries
              if (pruned.contains(jti) || pruned.size >= maxEntries)
                (pruned, false)
              else (pruned.updated(jti, expiresAt), true)
            }
          }
      }
    }
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
    * access token and the token's `cnf.jkt` thumbprint. Checks, per RFC 9449
    * §4.3: exactly one well-formed proof; `typ` is `dpop+jwt`; an allowed
    * asymmetric algorithm; a public-only `jwk` header that verifies the
    * signature; `htm`/`htu` match the request; `iat` is fresh; `ath` is the
    * SHA-256 hash of the access token; the proof key's thumbprint equals
    * `cnf.jkt`; and the `jti` has not been replayed.
    */
  def verify(
      req: Request[F],
      accessToken: String,
      expectedJkt: String
  ): F[Either[AuthError, Unit]]
}

object DpopVerifier {

  private val DpopJoseType = new JOSEObjectType("dpop+jwt")
  private val DpopHeader = ci"DPoP"

  /** `ath` claim value for an access token: base64url(SHA-256(token)). */
  def accessTokenHash(accessToken: String): String =
    Base64URL
      .encode(sha256(accessToken.getBytes(StandardCharsets.US_ASCII)))
      .toString

  private def sha256(bytes: Array[Byte]): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(bytes)

  private def constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(
      a.getBytes(StandardCharsets.US_ASCII),
      b.getBytes(StandardCharsets.US_ASCII)
    )

  def default[F[_]: Sync](
      config: DpopConfig,
      replayCache: DpopReplayCache[F],
      events: AuthEvents[F]
  ): DpopVerifier[F] = new DpopVerifier[F] {

    val algorithms: Set[JWSAlgorithm] = config.allowedAlgorithms

    def verify(
        req: Request[F],
        accessToken: String,
        expectedJkt: String
    ): F[Either[AuthError, Unit]] =
      req.headers.get(DpopHeader) match {
        case None =>
          fail(AuthError.InvalidDpopProof.Missing, "no DPoP header on request")
        case Some(values) if values.tail.nonEmpty =>
          fail(
            AuthError.InvalidDpopProof.Malformed,
            "multiple DPoP headers on request"
          )
        case Some(values) =>
          val proof = values.head.value
          if (proof.length > config.maxProofLength)
            fail(
              AuthError.InvalidDpopProof.Malformed,
              s"proof length ${proof.length}"
            )
          else
            Clock[F].realTimeInstant.flatMap { now =>
              Sync[F]
                .delay(checkProof(proof, req, accessToken, expectedJkt, now))
                .flatMap {
                  case Left((error, detail))     => fail(error, detail)
                  case Right((jti, retainUntil)) =>
                    replayCache.register(jti, retainUntil).flatMap {
                      case true  => ().asRight[AuthError].pure[F]
                      case false =>
                        fail(
                          AuthError.InvalidDpopProof.Replayed,
                          "jti already seen"
                        )
                    }
                }
            }
      }

    private def fail(
        error: AuthError,
        detail: String
    ): F[Either[AuthError, Unit]] =
      events.authFailed(error, detail).as(error.asLeft)

    /** All proof checks except replay; returns the proof's `jti` and how long
      * the replay cache must remember it.
      */
    private def checkProof(
        proof: String,
        req: Request[F],
        accessToken: String,
        expectedJkt: String,
        now: Instant
    ): Either[(AuthError, String), (String, Instant)] =
      try {
        val jwt = SignedJWT.parse(proof)
        val header = jwt.getHeader
        for {
          _ <- check(
            Option(header.getType).contains(DpopJoseType),
            "typ is not dpop+jwt"
          )
          _ <- check(
            config.allowedAlgorithms.contains(header.getAlgorithm),
            s"alg ${header.getAlgorithm} not allowed"
          )
          jwk <- Option(header.getJWK)
            .toRight((AuthError.InvalidDpopProof.Rejected, "no jwk header"))
          _ <- check(!jwk.isPrivate, "jwk header contains private key material")
          v <- verifierFor(jwk)
          ok <- catchJose(jwt.verify(v))
          _ <- check(ok, "proof signature is invalid")
          claims = jwt.getJWTClaimsSet
          jti <- Option(claims.getJWTID)
            .filter(j => j.nonEmpty && j.length <= config.maxJtiLength)
            .toRight(
              (AuthError.InvalidDpopProof.Rejected, "missing or oversized jti")
            )
          _ <- check(
            Option(claims.getStringClaim("htm")).contains(req.method.name),
            "htm does not match the request method"
          )
          _ <- check(
            htuMatches(Option(claims.getStringClaim("htu")), req),
            "htu does not match the request URI"
          )
          iat <- Option(claims.getIssueTime)
            .map(_.toInstant)
            .toRight((AuthError.InvalidDpopProof.Rejected, "missing iat"))
          maxBackdate = (config.proofMaxAge + config.clockSkew).toSeconds
          _ <- check(
            !iat.isBefore(now.minusSeconds(maxBackdate)),
            "proof is too old"
          )
          _ <- check(
            !iat.isAfter(now.plusSeconds(config.clockSkew.toSeconds)),
            "iat is in the future"
          )
          ath <- Option(claims.getStringClaim("ath"))
            .toRight((AuthError.InvalidDpopProof.Rejected, "missing ath"))
          _ <- check(
            constantTimeEquals(ath, accessTokenHash(accessToken)),
            "ath does not match the presented access token"
          )
          _ <- check(
            constantTimeEquals(jwk.computeThumbprint().toString, expectedJkt),
            "proof key thumbprint does not match the token's cnf.jkt"
          )
        } yield (jti, iat.plusSeconds(maxBackdate))
      } catch {
        case e: ParseException =>
          Left(
            (
              AuthError.InvalidDpopProof.Malformed,
              Option(e.getMessage).getOrElse("parse error")
            )
          )
        case e: JOSEException =>
          Left(
            (
              AuthError.InvalidDpopProof.Rejected,
              Option(e.getMessage).getOrElse("JOSE error")
            )
          )
      }

    private def check(
        cond: Boolean,
        detail: String
    ): Either[(AuthError, String), Unit] =
      Either.cond(cond, (), (AuthError.InvalidDpopProof.Rejected, detail))

    private def catchJose[A](a: => A): Either[(AuthError, String), A] =
      try Right(a)
      catch {
        case e: JOSEException =>
          Left(
            (
              AuthError.InvalidDpopProof.Rejected,
              Option(e.getMessage).getOrElse("JOSE error")
            )
          )
      }

    private def verifierFor(
        jwk: JWK
    ): Either[(AuthError, String), JWSVerifier] =
      catchJose {
        jwk match {
          case k: ECKey        => Some(new ECDSAVerifier(k))
          case k: RSAKey       => Some(new RSASSAVerifier(k))
          case k: OctetKeyPair => Some(new Ed25519Verifier(k))
          case _               => None
        }
      }.flatMap(
        _.toRight(
          (AuthError.InvalidDpopProof.Rejected, "unsupported jwk key type")
        )
      )

    /** RFC 9449 §4.3: `htu` must match the request URI, ignoring query and
      * fragment. Scheme and host compare case-insensitively; default ports are
      * normalized. Behind a TLS-terminating proxy the request often has no
      * scheme/authority of its own, so the authority falls back to the `Host`
      * header and the scheme to `https` (per [[DpopConfig.assumeTls]]).
      */
    private def htuMatches(htuClaim: Option[String], req: Request[F]): Boolean =
      htuClaim.exists { raw =>
        Uri.fromString(raw).toOption.exists { htu =>
          val expectedScheme =
            req.uri.scheme.getOrElse(
              if (config.assumeTls) Uri.Scheme.https else Uri.Scheme.http
            )
          val expectedAuthority = req.uri.authority.orElse(
            req.headers
              .get[Host]
              .map(h =>
                Uri.Authority(host = Uri.RegName(h.host), port = h.port)
              )
          )
          (htu.scheme, htu.authority, expectedAuthority) match {
            case (Some(scheme), Some(authority), Some(expected)) =>
              scheme.value.equalsIgnoreCase(expectedScheme.value) &&
              authority.host.value.equalsIgnoreCase(expected.host.value) &&
              effectivePort(authority.port, scheme) == effectivePort(
                expected.port,
                expectedScheme
              ) &&
              normalizedPath(htu.path) == normalizedPath(req.uri.path)
            case _ => false
          }
        }
      }

    private def effectivePort(port: Option[Int], scheme: Uri.Scheme): Int =
      port.getOrElse(if (scheme == Uri.Scheme.http) 80 else 443)

    private def normalizedPath(path: Uri.Path): String = {
      val rendered = path.renderString
      if (rendered.isEmpty) "/" else rendered
    }
  }
}
