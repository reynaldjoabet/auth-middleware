package auth
package accesstoken

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.ParseException
import java.util.Base64

import scala.jdk.CollectionConverters.*

import cats.effect.Sync
import cats.syntax.all.*

import com.github.benmanes.caffeine.cache.{Cache, Caffeine, Expiry}
import com.github.benmanes.caffeine.cache.stats.StatsCounter
import com.nimbusds.jose.jwk.source.{JWKSource, JWKSourceBuilder}
import com.nimbusds.jose.proc.{
  BadJOSEException,
  DefaultJOSEObjectTypeVerifier,
  JWSVerificationKeySelector,
  SecurityContext
}
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import com.nimbusds.jwt.proc.{DefaultJWTClaimsVerifier, DefaultJWTProcessor}
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation
import auth.revocation.{TokenDenylist, TokenIntrospection}

/**
  * Validates OAuth 2.0 JWT access tokens (RFC 9068 profile).
  */
trait AccessTokenValidator[F[_]] {

  /**
    * Fully validate a compact-serialized JWT: structure, JOSE `typ` header, signature against the
    * issuer's JWKS, issuer, audience, lifetime, required claims, the revocation denylist and (when
    * configured) RFC 7662 introspection. Returns a redaction-safe [[AuthError]] on the left;
    * internal diagnostics are reported via [[AuthEvents]].
    */
  def validate(token: String): F[Either[AuthError, AuthContext]]
}

object AccessTokenValidator {

  /**
    * Production wiring for access token validation: verification keys are fetched from
    * `config.jwksUri` and cached, with rate limiting, retries and outage tolerance, so key rotation
    * at the authorization server is picked up automatically and transient JWKS outages do not take
    * the API down.
    *
    * This validator is specifically for OAuth 2.0 access tokens (RFC 9068): it enforces required
    * claims (sub, exp, iat, client_id, jti), verifies issuer and audience, and supports optional
    * revocation checks via denylist and RFC 7662 introspection.
    *
    * @param config
    *   access token configuration (issuer, audience, JWKS URI, required claims)
    * @param events
    *   event sink for auth success/failure and diagnostics
    * @param denylist
    *   distributed revocation store (e.g. Redis); prevents use of revoked tokens
    * @param introspection
    *   optional RFC 7662 revocation check against the authorization server — the Redis-free
    *   alternative to a distributed [[TokenDenylist]] (the Duende pattern). Runs after local
    *   validation and the denylist; an inactive token is rejected `invalid_token`, an unreachable
    *   endpoint fails closed as 503. Build a second validator without it for route groups that
    *   should not pay the network hop.
    * @param telemetry
    *   latency/health instrumentation for this validator and the dependencies handed to it —
    *   including Nimbus's own JWKS cache lifecycle, which is otherwise entirely opaque. Defaults to
    *   [[AuthTelemetry.noop]].
    *
    * When `config.revocationCacheTtl` is positive the denylist is fronted by
    * [[TokenDenylist.cached]]; the telemetry sits beneath the cache, so the denylist metrics count
    * real store round trips only.
    */
  def default[F[_]: Sync](
      config: AccessTokenConfig,
      events: AuthEvents[F],
      denylist: TokenDenylist[F],
      introspection: Option[TokenIntrospection[F]] = None,
      telemetry: AuthTelemetry[F] = AuthTelemetry.noop[F]
  ): F[AccessTokenValidator[F]] =
    Sync[F]
      .delay {
        val retriever = telemetry.instrumentJwksRetriever(
          new DefaultResourceRetriever(
            config.httpConnectTimeout.toMillis.toInt,
            config.httpReadTimeout.toMillis.toInt,
            config.jwksSizeLimitBytes
          )
        )
        // The listener overloads are what enable each layer, so these carry the
        // same semantics as the plain `.retrying(true)` / `.outageTolerant(ttl)`
        // calls they replace — they just also report what the layer did.
        JWKSourceBuilder
          .create[SecurityContext](config.jwksUri.toURL, retriever)
          .cache(
            config.jwksCacheTtl.toMillis,
            config.jwksRefreshTimeout.toMillis,
            telemetry.jwksCacheListener[SecurityContext]
          )
          .retrying(telemetry.jwksRetryListener[SecurityContext])
          .outageTolerant(
            config.jwksOutageTtl.toMillis,
            telemetry.jwksOutageListener[SecurityContext]
          )
          .build()
      }
      .flatMap { keySource =>
        val instrumented = telemetry.instrumentDenylist(denylist)
        val revocation   =
          if (config.revocationCacheTtl > scala.concurrent.duration.Duration.Zero)
            TokenDenylist.cached(
              instrumented,
              config.revocationCacheTtl,
              config.revocationCacheMaxEntries
            )
          else instrumented.pure[F]
        revocation.map(d => build(config, keySource, events, d, introspection, telemetry))
      }

  /**
    * Build an access token validator over an explicit key source — used in tests and for non-HTTP
    * key distribution.
    *
    * Validates access tokens using the provided key source (instead of fetching from a remote JWKS
    * URI). Useful for testing, key distribution via configuration, or air-gapped deployments.
    *
    * @param config
    *   access token configuration
    * @param keySource
    *   explicit JWK source (not fetched remotely)
    * @param events
    *   event sink for diagnostics
    * @param denylist
    *   revocation store
    * @param introspection
    *   optional RFC 7662 introspection
    * @param telemetry
    *   instrumentation for the validator and its revocation dependencies; the key source is
    *   caller-supplied here, so nothing instruments it
    *
    * `config.revocationCacheTtl` is not applied here; wrap `denylist` in [[TokenDenylist.cached]]
    * yourself if wanted.
    */
  def withKeySource[F[_]: Sync](
      config: AccessTokenConfig,
      keySource: JWKSource[SecurityContext],
      events: AuthEvents[F],
      denylist: TokenDenylist[F],
      introspection: Option[TokenIntrospection[F]] = None,
      telemetry: AuthTelemetry[F] = AuthTelemetry.noop[F]
  ): AccessTokenValidator[F] =
    build(
      config,
      keySource,
      events,
      telemetry.instrumentDenylist(denylist),
      introspection,
      telemetry
    )

  // `denylist` arrives already instrumented (and possibly cached).
  private def build[F[_]: Sync](
      config: AccessTokenConfig,
      keySource: JWKSource[SecurityContext],
      events: AuthEvents[F],
      denylist: TokenDenylist[F],
      introspection: Option[TokenIntrospection[F]],
      telemetry: AuthTelemetry[F]
  ): AccessTokenValidator[F] =
    telemetry.instrumentValidator(
      new Impl[F](
        config,
        keySource,
        events,
        denylist,
        introspection.map(telemetry.instrumentIntrospection),
        telemetry.verifiedTokenCacheStats
      )
    )

  private final class Impl[F[_]: Sync](
      config: AccessTokenConfig,
      keySource: JWKSource[SecurityContext],
      events: AuthEvents[F],
      denylist: TokenDenylist[F],
      introspection: Option[TokenIntrospection[F]],
      cacheStats: Option[StatsCounter]
  ) extends AccessTokenValidator[F] {

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
      // The default implementation, DefaultJWTClaimsVerifier, checks exp / nbf (with clock-skew tolerance), and whatever exact-match/required claims you configured — iss, aud
      // public DefaultJWTClaimsVerifier(final Set<String> acceptedAudience,
      // 		final JWTClaimsSet exactMatchClaims,
      // 		final Set<String> requiredClaims,
      // 		final Set<String> prohibitedClaims)

      val claimsVerifier = new DefaultJWTClaimsVerifier[SecurityContext](
        Set(config.audience).asJava, // acceptedAudience
        new JWTClaimsSet.Builder()
          .issuer(config.issuer)
          .build(),                   // exactMatchClaims
        config.requiredClaims.asJava, // requiredClaims
        null                          // prohibitedClaims
      )
      claimsVerifier.setMaxClockSkew(config.clockSkew.toSeconds.toInt)
      p.setJWTClaimsSetVerifier(claimsVerifier)
      p
    }

    /**
      * Successfully verified tokens, keyed by base64url(SHA-256(token)) so raw tokens are never
      * retained. Only the signature/claims verification is cached — revocation runs every time.
      * Each entry expires at the earlier of the token's `exp` and `verifiedTokenCacheMaxTtl`.
      */
    private val verified: Option[Cache[String, AuthContext]] =
      Option.when(
        config.verifiedTokenCacheMaxEntries > 0 &&
          config.verifiedTokenCacheMaxTtl > scala.concurrent.duration.Duration.Zero
      ) {
        val maxTtlNanos = config.verifiedTokenCacheMaxTtl.toNanos
        val sized       = Caffeine.newBuilder().maximumSize(config.verifiedTokenCacheMaxEntries)
        cacheStats
          .fold(sized)(stats => sized.recordStats(() => stats))
          .expireAfter(new Expiry[String, AuthContext] {
            def expireAfterCreate(key: String, ctx: AuthContext, now: Long): Long = {
              val remainingMillis = ctx.expiresAt.toEpochMilli - System.currentTimeMillis()
              math.max(0L, math.min(maxTtlNanos, remainingMillis * 1_000_000L))
            }
            def expireAfterUpdate(
                key: String,
                ctx: AuthContext,
                now: Long,
                currentDuration: Long
            ): Long = currentDuration
            def expireAfterRead(
                key: String,
                ctx: AuthContext,
                now: Long,
                currentDuration: Long
            ): Long = currentDuration
          })
          .build[String, AuthContext]()
      }

    def validate(token: String): F[Either[AuthError, AuthContext]] =
      if (token.length > config.maxTokenLength)
        reject(
          AuthError.InvalidToken.Oversized,
          s"token length ${token.length}"
        )
      else
        verified match {
          case None        => verify(token, None)
          case Some(cache) =>
            Sync[F]
              .delay {
                val key = tokenKey(token)
                (key, Option(cache.getIfPresent(key)))
              }
              .flatMap {
                case (_, Some(ctx)) => checkDenylist(token, ctx)
                case (key, None)    => verify(token, Some((cache, key)))
              }
        }

    private def verify(
        token: String,
        remember: Option[(Cache[String, AuthContext], String)]
    ): F[Either[AuthError, AuthContext]] =
      // `blocking` because the key selector may fetch the JWKS over HTTP (a
      // cold cache or an unknown `kid`). Only cache misses get here; on the
      // work-stealing pool `blocking` hands the worker off rather than
      // shifting threads.
      Sync[F]
        .blocking(processor.process(SignedJWT.parse(token), null))
        .attempt
        .flatMap {
          // The finished context is what gets cached, so a hit skips re-reading
          // and re-refining the claims as well as the signature check.
          case Right(claims) =>
            contextOf(claims) match {
              case Left((err, detail)) => reject(err, detail)
              case Right(ctx)          =>
                remember.fold(Sync[F].unit) { case (cache, key) =>
                  Sync[F].delay(cache.put(key, ctx))
                } *> checkDenylist(token, ctx)
            }
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
        ctx: AuthContext
    ): F[Either[AuthError, AuthContext]] =
      Option(ctx.claims.getJWTID) match {
        case None =>
          checkIntrospection(token, ctx)
        case Some(jti) =>
          // A store we cannot reach proves nothing: fail closed with 503.
          denylist.isRevoked(jti).attempt.flatMap {
            case Right(true) =>
              reject(AuthError.InvalidToken.Revoked, s"jti $jti is denylisted")
            case Right(false) => checkIntrospection(token, ctx)
            case Left(e)      =>
              reject(
                AuthError.ValidationUnavailable,
                s"revocation store unavailable: ${e.getMessage}"
              )
          }
      }

    // RFC 7662 revocation check against the AS (the Duende `introspect` flag):
    // last, because it is the only step that costs a network hop. Inactive →
    // revoked; endpoint unavailable → fail closed as 503, never accept a token
    // we cannot prove active.
    private def checkIntrospection(
        token: String,
        ctx: AuthContext
    ): F[Either[AuthError, AuthContext]] =
      introspection match {
        case None    => accept(ctx)
        case Some(i) =>
          i.check(token).flatMap {
            case TokenIntrospection.Result.Active   => accept(ctx)
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

    private def accept(ctx: AuthContext): F[Either[AuthError, AuthContext]] =
      events.authSucceeded(ctx).as(ctx.asRight)

    /**
      * The authenticated principal a verified claims set describes, or why it cannot be one. Pure
      * and deterministic in the claims, which is what makes the result safe to cache.
      */
    private def contextOf(claims: JWTClaimsSet): Either[(AuthError, String), AuthContext] =
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
        // `exp` is in the default requiredClaims, but that set is
        // operator-configurable — reject rather than NPE if it was relaxed.
        expiresAt <- Option(claims.getExpirationTime)
                       .map(_.toInstant)
                       .toRight((AuthError.InvalidToken.Rejected, "missing exp claim"))
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
        expiresAt = expiresAt,
        acr = stringClaim(claims, "acr").flatMap(Acr.option),
        authTime = dateClaim(claims, "auth_time"),
        confirmation = confirmation,
        claims = claims
      )

    /**
      * Read the `cnf` confirmation (Nimbus-parsed): `jkt` (DPoP, RFC 9449) or `x5t#S256` (mTLS, RFC
      * 8705). A present-but-malformed `cnf` is reported as [[Cnf.Invalid]] so a broken binding
      * fails closed rather than silently downgrading to an unbound token. Enforcement of the
      * binding itself happens in the middleware, which has access to the request.
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

    private def tokenKey(token: String): String =
      Base64.getUrlEncoder.withoutPadding.encodeToString(
        MessageDigest
          .getInstance("SHA-256")
          .digest(token.getBytes(StandardCharsets.US_ASCII))
      )

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
