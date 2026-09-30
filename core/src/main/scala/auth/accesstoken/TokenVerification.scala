package auth
package accesstoken

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.ParseException
import java.util.Base64

import scala.concurrent.duration.Duration
import scala.jdk.CollectionConverters.*

import com.github.benmanes.caffeine.cache.{Cache, Caffeine, Expiry}
import com.github.benmanes.caffeine.cache.stats.StatsCounter
import com.nimbusds.jose.jwk.{JWKMatcher, JWKSelector}
import com.nimbusds.jose.jwk.source.{
  CachingJWKSetSource,
  JWKSource,
  JWKSourceBuilder,
  OutageTolerantJWKSetSource,
  RetryingJWKSetSource
}
import com.nimbusds.jose.proc.{
  BadJOSEException,
  DefaultJOSEObjectTypeVerifier,
  JWSVerificationKeySelector,
  SecurityContext
}
import com.nimbusds.jose.util.{DefaultResourceRetriever, ResourceRetriever}
import com.nimbusds.jose.util.events.EventListener
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import com.nimbusds.jwt.proc.{DefaultJWTClaimsVerifier, DefaultJWTProcessor}
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation

/**
  * The framework-independent core of access-token validation: key sources, the Nimbus processor,
  * claims → [[AuthContext]], failure classification and the verified-token cache.
  *
  * Everything here is either pure or plain synchronous JVM code. The http4s/cats-effect
  * `AccessTokenValidator` in the http4s service and the ZIO validator (the `zio` module) wrap these
  * calls in their own effects, so the two make the same decisions by construction and differ only
  * in how they run them.
  */
object TokenVerification {

  /**
    * The JWKS-backed key source: cached, refreshed on a schedule ahead of expiry, retried, and
    * outage-tolerant. The listeners only report what each layer did (see `AuthTelemetry`); they
    * default to no-ops.
    */
  def keySource(
      config: AccessTokenConfig,
      retriever: Option[ResourceRetriever] = None,
      cacheListener: EventListener[CachingJWKSetSource[SecurityContext], SecurityContext] = _ => (),
      retryListener: EventListener[RetryingJWKSetSource[SecurityContext], SecurityContext] = _ =>
        (),
      outageListener: EventListener[OutageTolerantJWKSetSource[SecurityContext], SecurityContext] =
        _ => ()
  ): JWKSource[SecurityContext] =
    JWKSourceBuilder
      .create[SecurityContext](config.jwksUri.toURL, retriever.getOrElse(retrieverFor(config)))
      .cache(config.jwksCacheTtl.toMillis, config.jwksRefreshTimeout.toMillis, cacheListener)
      // Scheduled: refresh in the background before expiry even on a quiet
      // node, rather than on whichever request happens to arrive late.
      .refreshAheadCache(JWKSourceBuilder.DEFAULT_REFRESH_AHEAD_TIME, true, cacheListener)
      .retrying(retryListener)
      .outageTolerant(config.jwksOutageTtl.toMillis, outageListener)
      .build()

  /**
    * The HTTP retriever for `config.jwksUri`, with its connect/read timeouts and size limit.
    */
  def retrieverFor(config: AccessTokenConfig): DefaultResourceRetriever =
    new DefaultResourceRetriever(
      config.httpConnectTimeout.toMillis.toInt,
      config.httpReadTimeout.toMillis.toInt,
      config.jwksSizeLimitBytes
    )

  /**
    * Fetch the key set once through the full cache/retry stack, throwing an exception an operator
    * can act on if it cannot be fetched or is empty. Blocking.
    */
  def requireKeys(config: AccessTokenConfig, keySource: JWKSource[SecurityContext]): Unit = {
    val keys =
      try keySource.get(new JWKSelector(new JWKMatcher.Builder().build()), null)
      catch {
        case e: Exception =>
          throw new IllegalStateException(
            s"Cannot fetch signing keys from ${config.jwksUri} at startup; refusing to serve " +
              "without them",
            e
          )
      }
    if (keys.isEmpty)
      throw new IllegalStateException(
        s"The key set at ${config.jwksUri} contains no keys; refusing to serve without them"
      )
  }

  /**
    * The Nimbus processor enforcing `config`: JOSE `typ`, allowed algorithms, signature against
    * `keySource`, issuer, audience, required claims and lifetime (with clock skew).
    */
  def processor(
      config: AccessTokenConfig,
      keySource: JWKSource[SecurityContext]
  ): DefaultJWTProcessor[SecurityContext] = {
    val p = new DefaultJWTProcessor[SecurityContext]()
    p.setJWSTypeVerifier(
      new DefaultJOSEObjectTypeVerifier[SecurityContext](config.acceptedTokenTypes.toSeq*)
    )
    p.setJWSKeySelector(
      new JWSVerificationKeySelector[SecurityContext](config.allowedAlgorithms.asJava, keySource)
    )
    // DefaultJWTClaimsVerifier checks exp / nbf (with clock-skew tolerance) and
    // the exact-match (iss) and required claims, plus the accepted audience.
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

  /**
    * Parse and verify `token`. Throws Nimbus's exceptions (see [[failureOf]]). May block: the key
    * selector fetches the JWKS on a cold cache or an unknown `kid`.
    */
  def verify(processor: DefaultJWTProcessor[SecurityContext], token: String): JWTClaimsSet =
    processor.process(SignedJWT.parse(token), null)

  /**
    * The client-facing error for a verification failure, with internal detail for logs, or `None`
    * when the throwable is not a verification outcome (a bug, to be propagated).
    */
  def failureOf(e: Throwable): Option[(AuthError, String)] =
    e match {
      case e: ParseException     => Some((AuthError.InvalidToken.Malformed, e.getMessage))
      case e: BadJOSEException   => Some((AuthError.InvalidToken.Rejected, e.getMessage))
      case e: KeySourceException => Some((AuthError.ValidationUnavailable, e.getMessage))
      case e: JOSEException      => Some((AuthError.InvalidToken.Rejected, e.getMessage))
      case _                     => None
    }

  /**
    * Successfully verified tokens, keyed by [[tokenKey]] so raw tokens are never retained. Only the
    * signature/claims verification is cached — revocation runs every time. Each entry expires at
    * the earlier of the token's `exp` and `verifiedTokenCacheMaxTtl`. `None` when disabled.
    */
  def verifiedTokenCache(
      config: AccessTokenConfig,
      stats: Option[StatsCounter]
  ): Option[Cache[String, AuthContext]] =
    Option.when(
      config.verifiedTokenCacheMaxEntries > 0 && config.verifiedTokenCacheMaxTtl > Duration.Zero
    ) {
      val maxTtlNanos = config.verifiedTokenCacheMaxTtl.toNanos
      val sized       = Caffeine.newBuilder().maximumSize(config.verifiedTokenCacheMaxEntries)
      stats
        .fold(sized)(s => sized.recordStats(() => s))
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

  /**
    * Cache key for a token: base64url(SHA-256(token)).
    */
  def tokenKey(token: String): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(
      MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII))
    )

  /**
    * The authenticated principal a verified claims set describes, or why it cannot be one. Pure and
    * deterministic in the claims, which is what makes the result safe to cache.
    */
  def contextOf(claims: JWTClaimsSet): Either[(AuthError, String), AuthContext] =
    for {
      // `sub` is required (RFC 9068 §2.2 — present even for client_credentials,
      // where it equals the client_id). Its presence is also enforced by
      // Nimbus via `config.requiredClaims`.
      sub <- Option(claims.getSubject)
               .toRight((AuthError.InvalidToken.Rejected, "missing sub claim"))
      subject <- Subject.either(sub).left.map(m => (AuthError.InvalidToken.Rejected, m))
      tokenId <- Option(claims.getJWTID) match {
                   case None    => Right(None)
                   case Some(j) =>
                     ReceivedJwtId.either(j) match {
                       case Right(id) => Right(Some(id))
                       case Left(m)   => Left((AuthError.InvalidToken.Rejected, m))
                     }
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
    * 8705). A present-but-malformed `cnf` is reported as [[Cnf.Invalid]] so a broken binding fails
    * closed rather than silently downgrading to an unbound token. Enforcement of the binding itself
    * happens in the middleware, which has access to the request.
    */
  private def confirmationOf(claims: JWTClaimsSet): Cnf = {
    val jkt = Option(JWKThumbprintConfirmation.parse(claims)).map(_.getValue.toString)
    val x5t = Option(X509CertificateConfirmation.parse(claims)).map(_.getValue.toString)
    (jkt, x5t) match {
      case (None, None)    => Cnf.Unbound
      case (Some(j), None) =>
        JwkThumbprint.option(j) match {
          case Some(t) => Cnf.Bound(ConfirmationClaim.DPoP(t))
          case None    => Cnf.Invalid("cnf.jkt is not a valid base64url SHA-256 thumbprint")
        }
      case (None, Some(c)) =>
        CertificateThumbprint.option(c) match {
          case Some(t) => Cnf.Bound(ConfirmationClaim.MutualTls(t))
          case None    => Cnf.Invalid("cnf.x5t#S256 is not a valid base64url SHA-256 thumbprint")
        }
      case (Some(_), Some(_)) => Cnf.Invalid("cnf carries both jkt and x5t#S256")
    }
  }

  private def stringClaim(claims: JWTClaimsSet, name: String): Option[String] =
    claims.getClaim(name) match {
      case s: String => Some(s)
      case _         => None
    }

  private def dateClaim(claims: JWTClaimsSet, name: String): Option[java.time.Instant] =
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
          case l: java.util.List[?] => l.asScala.collect { case s: String => s }.toList
          case _                    => Nil
        }
    }

}
