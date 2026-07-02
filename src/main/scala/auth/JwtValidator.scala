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
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation

/** Validates OAuth 2.0 JWT access tokens (RFC 9068 profile). */
trait JwtValidator[F[_]] {

  /** Fully validate a compact-serialized JWT: structure, JOSE `typ` header,
    * signature against the issuer's JWKS, issuer, audience, lifetime, required
    * claims, the revocation denylist and (when configured) RFC 7662
    * introspection. Returns a redaction-safe [[AuthError]] on the left;
    * internal diagnostics are reported via [[AuthEvents]].
    */
  def validate(token: String): F[Either[AuthError, AuthContext]]
}

object JwtValidator {

  /** Production wiring: verification keys are fetched from `config.jwksUri` and
    * cached, with rate limiting, retries and outage tolerance, so key rotation
    * at the authorization server is picked up automatically and transient JWKS
    * outages do not take the API down.
    *
    * @param introspection
    *   optional RFC 7662 revocation check against the authorization server —
    *   the Redis-free alternative to a distributed [[TokenDenylist]] (the
    *   Duende pattern). Runs after local validation and the denylist; an
    *   inactive token is rejected `invalid_token`, an unreachable endpoint
    *   fails closed as 503. Build a second validator without it for route
    *   groups that should not pay the network hop.
    */
  def remote[F[_]: Sync](
      config: AuthConfig,
      events: AuthEvents[F],
      denylist: TokenDenylist[F],
      introspection: Option[TokenIntrospection[F]] = None
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
      .map(fromKeySource(config, _, events, denylist, introspection))

  /** Build a validator over an explicit key source — used in tests and for
    * non-HTTP key distribution.
    */
  def fromKeySource[F[_]: Sync](
      config: AuthConfig,
      keySource: JWKSource[SecurityContext],
      events: AuthEvents[F],
      denylist: TokenDenylist[F],
      introspection: Option[TokenIntrospection[F]] = None
  ): JwtValidator[F] =
    new Impl[F](config, keySource, events, denylist, introspection)

  private final class Impl[F[_]: Sync](
      config: AuthConfig,
      keySource: JWKSource[SecurityContext],
      events: AuthEvents[F],
      denylist: TokenDenylist[F],
      introspection: Option[TokenIntrospection[F]]
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
            case Right(claims)           => checkDenylist(token, claims)
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

    // `jti` presence is governed solely by `config.requiredClaims` (Nimbus rejects
    // a missing required claim before we get here). A token reaching this point
    // with no `jti` therefore has `jti` deliberately optional, so there is nothing
    // to look up — keep `"jti"` in requiredClaims (the default does) so tokens
    // cannot dodge the denylist by omitting it.
    private def checkDenylist(
        token: String,
        claims: JWTClaimsSet
    ): F[Either[AuthError, AuthContext]] =
      Option(claims.getJWTID) match {
        case None =>
          checkIntrospection(token, claims)
        case Some(jti) =>
          denylist.isRevoked(jti).flatMap {
            case true =>
              reject(AuthError.InvalidToken.Revoked, s"jti $jti is denylisted")
            case false => checkIntrospection(token, claims)
          }
      }

    // RFC 7662 revocation check against the AS (the Duende `introspect` flag):
    // last, because it is the only step that costs a network hop. Inactive →
    // revoked; endpoint unavailable → fail closed as 503, never accept a token
    // we cannot prove active.
    private def checkIntrospection(
        token: String,
        claims: JWTClaimsSet
    ): F[Either[AuthError, AuthContext]] =
      introspection match {
        case None    => accept(claims)
        case Some(i) =>
          i.check(token).flatMap {
            case TokenIntrospection.Result.Active   => accept(claims)
            case TokenIntrospection.Result.Inactive =>
              reject(
                AuthError.InvalidToken.Revoked,
                "introspection reports token inactive"
              )
            case TokenIntrospection.Result.Unavailable =>
              reject(
                AuthError.ValidationUnavailable,
                "introspection endpoint unavailable"
              )
          }
      }

    private def accept(
        claims: JWTClaimsSet
    ): F[Either[AuthError, AuthContext]] = {
      val built: Either[(AuthError, String), AuthContext] =
        for {
          // `sub` is required (RFC 9068 §2.2 — present even for client_credentials,
          // where it equals the client_id). Its presence is also enforced by
          // Nimbus via `config.requiredClaims`.
          sub <- Option(claims.getSubject)
            .toRight((AuthError.InvalidToken.Rejected, "missing sub claim"))
          subject <- Subject
            .either(sub)
            .left
            .map(m => (AuthError.InvalidToken.Rejected, m))
          tokenId <- Option(claims.getJWTID) match {
            case None    => Right(None)
            case Some(j) =>
              ReceivedJwtId
                .either(j)
                .bimap(m => (AuthError.InvalidToken.Rejected, m), Some(_))
          }
          // Fail closed on a present-but-malformed cnf: never silently downgrade a
          // sender-constrained token to an unbound one.
          confirmation <- confirmationOf(claims) match {
            case Cnf.Unbound    => Right(None)
            case Cnf.Bound(c)   => Right(Some(c))
            case Cnf.Invalid(r) => Left((AuthError.InvalidToken.Rejected, r))
          }
        } yield AuthContext(
          subject = subject,
          clientId = stringClaim(claims, "client_id")
            .orElse(stringClaim(claims, "azp"))
            .flatMap(ClientId.option),
          scopes = rawScopeTokens(claims).flatMap(ScopeToken.option).toSet,
          tokenId = tokenId,
          expiresAt = claims.getExpirationTime.toInstant,
          acr = stringClaim(claims, "acr").flatMap(Acr.option),
          authTime = dateClaim(claims, "auth_time"),
          confirmation = confirmation,
          claims = claims
        )
      built match {
        case Right(ctx)       => events.authSucceeded(ctx).as(ctx.asRight)
        case Left((err, det)) => reject(err, det)
      }
    }

    /** Read the `cnf` confirmation (Nimbus-parsed): `jkt` (DPoP, RFC 9449) or
      * `x5t#S256` (mTLS, RFC 8705). A present-but-malformed `cnf` is reported
      * as [[Cnf.Invalid]] so a broken binding fails closed rather than silently
      * downgrading to an unbound token. Enforcement of the binding itself
      * happens in the middleware, which has access to the request.
      */
    private def confirmationOf(claims: JWTClaimsSet): Cnf = {
      val jkt =
        Option(JWKThumbprintConfirmation.parse(claims)).map(_.getValue.toString)
      val x5t = Option(X509CertificateConfirmation.parse(claims))
        .map(_.getValue.toString)
      (jkt, x5t) match {
        case (None, None)    => Cnf.Unbound
        case (Some(j), None) =>
          JwkThumbprint.option(j) match {
            case Some(t) => Cnf.Bound(ConfirmationClaim.DPoP(t))
            case None    =>
              Cnf.Invalid("cnf.jkt is not a valid base64url SHA-256 thumbprint")
          }
        case (None, Some(c)) =>
          CertificateThumbprint.option(c) match {
            case Some(t) => Cnf.Bound(ConfirmationClaim.MutualTls(t))
            case None    =>
              Cnf.Invalid(
                "cnf.x5t#S256 is not a valid base64url SHA-256 thumbprint"
              )
          }
        case (Some(_), Some(_)) =>
          Cnf.Invalid("cnf carries both jkt and x5t#S256")
      }
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
    // and `scp` as a JSON string array (Okta, Microsoft Entra ID). Returns the
    // raw, unrefined candidates; `ScopeToken.option` refines each and drops malformed.
    private def rawScopeTokens(claims: JWTClaimsSet): List[String] =
      claims.getClaim("scope") match {
        case s: String => s.split(' ').iterator.filter(_.nonEmpty).toList
        case _         =>
          claims.getClaim("scp") match {
            case l: java.util.List[?] =>
              l.asScala.collect { case s: String => s }.toList
            case _ => Nil
          }
      }
  }
}
