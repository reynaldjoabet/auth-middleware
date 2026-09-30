package auth
package accesstoken

import cats.effect.{Resource, Sync}
import cats.syntax.all.*

import com.github.benmanes.caffeine.cache.stats.StatsCounter
import com.github.benmanes.caffeine.cache.Cache
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import auth.revocation.{SubjectRevocations, TokenDenylist, TokenIntrospection}

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
    *
    * Keys are fetched during acquisition, and acquisition fails if they cannot be: a node that
    * cannot verify a single token must not report ready and take traffic, and the first requests
    * after a deploy must not all queue behind the same cold fetch. After that the key set is
    * refreshed on a schedule, ahead of expiry, so no request waits on a routine refresh. The
    * refresh thread is stopped when the `Resource` is released.
    */
  def default[F[_]: Sync](
      config: AccessTokenConfig,
      events: AuthEvents[F],
      denylist: TokenDenylist[F],
      introspection: Option[TokenIntrospection[F]] = None,
      telemetry: AuthTelemetry[F] = AuthTelemetry.noop[F]
  ): Resource[F, AccessTokenValidator[F]] =
    Resource
      .make(Sync[F].delay {
        TokenVerification.keySource(
          config,
          retriever = Some(
            telemetry.instrumentJwksRetriever(TokenVerification.retrieverFor(config))
          ),
          cacheListener = telemetry.jwksCacheListener[SecurityContext],
          retryListener = telemetry.jwksRetryListener[SecurityContext],
          outageListener = telemetry.jwksOutageListener[SecurityContext]
        )
      }) {
        case closeable: java.io.Closeable => Sync[F].blocking(closeable.close())
        case _                            => Sync[F].unit
      }
      .evalTap(keySource => Sync[F].blocking(TokenVerification.requireKeys(config, keySource)))
      .evalMap { keySource =>
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

    private val processor: DefaultJWTProcessor[SecurityContext] =
      TokenVerification.processor(config, keySource)

    private val verified: Option[Cache[String, AuthContext]] =
      TokenVerification.verifiedTokenCache(config, cacheStats)

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
                val key = TokenVerification.tokenKey(token)
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
        .blocking(TokenVerification.verify(processor, token))
        .attempt
        .flatMap {
          // The finished context is what gets cached, so a hit skips re-reading
          // and re-refining the claims as well as the signature check.
          case Right(claims) =>
            TokenVerification.contextOf(claims) match {
              case Left((err, detail)) => reject(err, detail)
              case Right(ctx)          =>
                remember.fold(Sync[F].unit) { case (cache, key) =>
                  Sync[F].delay(cache.put(key, ctx))
                } *> checkDenylist(token, ctx)
            }
          case Left(e) =>
            TokenVerification.failureOf(e) match {
              case Some((err, detail)) => reject(err, detail)
              case None                => Sync[F].raiseError(e)
            }
        }

    // `jti` presence is governed solely by `config.requiredClaims` (Nimbus rejects
    // a missing required claim before we get here). A token reaching this point
    // with no `jti` therefore has `jti` deliberately optional, so there is nothing
    // to look up — keep `"jti"` in requiredClaims (the default does) so tokens
    // cannot dodge the denylist by omitting it.
    private def checkDenylist(
        token: String,
        ctx: AuthContext
    ): F[Either[AuthError, AuthContext]] = {
      val byTokenId: F[Option[String]] =
        Option(ctx.claims.getJWTID) match {
          case None      => Sync[F].pure(None)
          case Some(jti) =>
            denylist.isRevoked(jti).map(Option.when(_)(s"jti $jti is denylisted"))
        }
      // Subject-wide revocation (a role change, "sign out everywhere"): covers
      // this token if it was issued before the subject's cut-off.
      val bySubject: F[Option[String]] =
        denylist.subjects match {
          case None           => Sync[F].pure(None)
          case Some(subjects) =>
            subjects.revokedBefore(ctx.subject.value).map {
              case Some(before) if SubjectRevocations.covers(before, ctx.issuedAt) =>
                Some(s"tokens of subject ${ctx.subject} issued before $before are revoked")
              case _ => None
            }
        }
      // A store we cannot reach proves nothing: fail closed with 503.
      (byTokenId, bySubject).mapN(_.orElse(_)).attempt.flatMap {
        case Right(Some(detail)) => reject(AuthError.InvalidToken.Revoked, detail)
        case Right(None)         => checkIntrospection(token, ctx)
        case Left(e)             =>
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

    private def reject(
        error: AuthError,
        detail: String
    ): F[Either[AuthError, AuthContext]] =
      events.authFailed(error, Option(detail).getOrElse("")).as(error.asLeft)

  }

}
