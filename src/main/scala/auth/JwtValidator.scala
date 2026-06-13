package auth

import java.text.ParseException

import scala.jdk.CollectionConverters.*

import cats.effect.Sync
import cats.syntax.all.*
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.jwk.source.{JWKSource, JWKSourceBuilder}
import com.nimbusds.jose.proc.{
  BadJOSEException,
  DefaultJOSEObjectTypeVerifier,
  JWSVerificationKeySelector,
  SecurityContext
}
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jwt.proc.{DefaultJWTClaimsVerifier, DefaultJWTProcessor}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}

/** Validates OAuth 2.0 JWT access tokens (RFC 9068 profile). */
trait JwtValidator[F[_]] {

  /** Fully validate a compact-serialized JWT: structure, JOSE `typ` header,
    * signature against the issuer's JWKS, issuer, audience, lifetime, required
    * claims and the revocation denylist. Returns a redaction-safe [[AuthError]]
    * on the left; internal diagnostics are reported via [[AuthEvents]].
    */
  def validate(token: String): F[Either[AuthError, AuthContext]]
}

object JwtValidator {

  /** Production wiring: verification keys are fetched from `config.jwksUri` and
    * cached, with rate limiting, retries and outage tolerance, so key rotation
    * at the authorization server is picked up automatically and transient JWKS
    * outages do not take the API down.
    */
  def remote[F[_]: Sync](
      config: AuthConfig,
      events: AuthEvents[F],
      denylist: TokenDenylist[F]
  ): F[JwtValidator[F]] =
    Sync[F]
      .delay {
        val retriever = new DefaultResourceRetriever(
          config.httpConnectTimeout.toMillis.toInt,
          config.httpReadTimeout.toMillis.toInt,
          config.jwksSizeLimitBytes
        )
        JWKSourceBuilder
          .create[SecurityContext](config.jwksUri.toURL, retriever)
          .cache(
            config.jwksCacheTtl.toMillis,
            config.jwksRefreshTimeout.toMillis
          )
          .retrying(true)
          .outageTolerant(config.jwksOutageTtl.toMillis)
          .build()
      }
      .map(fromKeySource(config, _, events, denylist))

  /** Build a validator over an explicit key source — used in tests and for
    * non-HTTP key distribution.
    */
  def fromKeySource[F[_]: Sync](
      config: AuthConfig,
      keySource: JWKSource[SecurityContext],
      events: AuthEvents[F],
      denylist: TokenDenylist[F]
  ): JwtValidator[F] =
    new Impl[F](config, keySource, events, denylist)

  private final class Impl[F[_]: Sync](
      config: AuthConfig,
      keySource: JWKSource[SecurityContext],
      events: AuthEvents[F],
      denylist: TokenDenylist[F]
  ) extends JwtValidator[F] {

    private val processor: DefaultJWTProcessor[SecurityContext] = {
      val p = new DefaultJWTProcessor[SecurityContext]()
      p.setJWSTypeVerifier(
        new DefaultJOSEObjectTypeVerifier[SecurityContext](
          config.acceptedTokenTypes.toSeq*
        )
      )
      p.setJWSKeySelector(
        new JWSVerificationKeySelector[SecurityContext](
          config.allowedAlgorithms.asJava,
          keySource
        )
      )
      val claimsVerifier = new DefaultJWTClaimsVerifier[SecurityContext](
        Set(config.audience).asJava,
        new JWTClaimsSet.Builder().issuer(config.issuer).build(),
        config.requiredClaims.asJava,
        null
      )
      claimsVerifier.setMaxClockSkew(config.clockSkew.toSeconds.toInt)
      p.setJWTClaimsSetVerifier(claimsVerifier)
      p
    }

    def validate(token: String): F[Either[AuthError, AuthContext]] =
      if (token.length > config.maxTokenLength)
        reject(
          AuthError.InvalidToken.Oversized,
          s"token length ${token.length}"
        )
      else
        // `blocking` because the key selector may fetch the JWKS over HTTP.
        Sync[F]
          .blocking(processor.process(SignedJWT.parse(token), null))
          .attempt
          .flatMap {
            case Right(claims)           => checkDenylist(claims)
            case Left(e: ParseException) =>
              reject(AuthError.InvalidToken.Malformed, e.getMessage)
            case Left(e: BadJOSEException) =>
              reject(AuthError.InvalidToken.Rejected, e.getMessage)
            case Left(e: KeySourceException) =>
              reject(AuthError.ValidationUnavailable, e.getMessage)
            case Left(e: JOSEException) =>
              reject(AuthError.InvalidToken.Rejected, e.getMessage)
            case Left(other) => Sync[F].raiseError(other)
          }

    private def checkDenylist(
        claims: JWTClaimsSet
    ): F[Either[AuthError, AuthContext]] =
      Option(claims.getJWTID) match {
        case None if config.requireTokenId =>
          reject(AuthError.InvalidToken.MissingTokenId, "jti absent")
        case None =>
          accept(claims)
        case Some(jti) =>
          denylist.isRevoked(jti).flatMap {
            case true =>
              reject(AuthError.InvalidToken.Revoked, s"jti $jti is denylisted")
            case false => accept(claims)
          }
      }

    private def accept(
        claims: JWTClaimsSet
    ): F[Either[AuthError, AuthContext]] = {
      val (jkt, x5t) = confirmationClaims(claims)
      val ctx = AuthContext(
        subject = claims.getSubject,
        clientId =
          stringClaim(claims, "client_id").orElse(stringClaim(claims, "azp")),
        scopes = extractScopes(claims),
        tokenId = Option(claims.getJWTID),
        expiresAt = claims.getExpirationTime.toInstant,
        acr = stringClaim(claims, "acr"),
        authTime = dateClaim(claims, "auth_time"),
        dpopKeyThumbprint = jkt,
        certificateThumbprint = x5t,
        claims = claims
      )
      events.authSucceeded(ctx).as(ctx.asRight)
    }

    /** RFC 7800 `cnf` confirmation claim: `jkt` (DPoP, RFC 9449) and `x5t#S256`
      * (mTLS, RFC 8705). Enforcement happens in the middleware, which has
      * access to the request.
      */
    private def confirmationClaims(
        claims: JWTClaimsSet
    ): (Option[String], Option[String]) =
      claims.getClaim("cnf") match {
        case cnf: java.util.Map[?, ?] =>
          def str(key: String): Option[String] = cnf.get(key) match {
            case s: String => Some(s)
            case _         => None
          }
          (str("jkt"), str("x5t#S256"))
        case _ => (None, None)
      }

    private def reject(
        error: AuthError,
        detail: String
    ): F[Either[AuthError, AuthContext]] =
      events.authFailed(error, Option(detail).getOrElse("")).as(error.asLeft)

    private def stringClaim(
        claims: JWTClaimsSet,
        name: String
    ): Option[String] =
      claims.getClaim(name) match {
        case s: String => Some(s)
        case _         => None
      }

    private def dateClaim(
        claims: JWTClaimsSet,
        name: String
    ): Option[java.time.Instant] =
      try Option(claims.getDateClaim(name)).map(_.toInstant)
      catch { case _: ParseException => None }

    // Both forms seen in the wild: `scope` as a space-delimited string (RFC 9068)
    // and `scp` as a JSON string array (Okta, Microsoft Entra ID).
    private def extractScopes(claims: JWTClaimsSet): Set[String] =
      claims.getClaim("scope") match {
        case s: String => s.split(' ').iterator.filter(_.nonEmpty).toSet
        case _         =>
          claims.getClaim("scp") match {
            case l: java.util.List[?] =>
              l.asScala.collect { case s: String => s }.toSet
            case _ => Set.empty
          }
      }
  }
}
