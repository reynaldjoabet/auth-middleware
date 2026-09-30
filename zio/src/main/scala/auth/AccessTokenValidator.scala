package auth

import auth.accesstoken.{AccessTokenConfig, TokenVerification}
import com.github.benmanes.caffeine.cache.Cache
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import zio.*

/**
  * RFC 9068 access-token validation on ZIO — the counterpart of the http4s service's
  * `auth.accesstoken.AccessTokenValidator`, running the same steps in the same order through the
  * shared [[auth.accesstoken.TokenVerification]] core:
  *
  *   1. reject oversized tokens
  *   1. verified-token cache lookup; on a miss, Nimbus verification (signature, `typ`, `iss`,
  *      `aud`, lifetime, required claims) and claims → [[AuthContext]], cached until `exp` or the
  *      TTL cap
  *   1. the revocation denylist on every request, failing closed (`503`) when it cannot answer
  *
  * Introspection (RFC 7662) is not wired in this implementation.
  */
final class AccessTokenValidator(
    config: AccessTokenConfig,
    keySource: JWKSource[SecurityContext],
    denylist: TokenDenylist,
    events: AuthEvents
) {

  private val processor = TokenVerification.processor(config, keySource)
  private val verified  = TokenVerification.verifiedTokenCache(config, stats = None)

  def validate(token: String): UIO[Either[AuthError, AuthContext]] =
    if (token.length > config.maxTokenLength)
      reject(AuthError.InvalidToken.Oversized, s"token length ${token.length}")
    else
      verified match {
        case None        => verify(token, None)
        case Some(cache) =>
          ZIO.suspendSucceed {
            val key = TokenVerification.tokenKey(token)
            Option(cache.getIfPresent(key)) match {
              case Some(ctx) => checkDenylist(ctx)
              case None      => verify(token, Some((cache, key)))
            }
          }
      }

  // `attemptBlocking` because the key selector may fetch the JWKS over HTTP (a
  // cold cache or an unknown `kid`). Only cache misses get here.
  private def verify(
      token: String,
      remember: Option[(Cache[String, AuthContext], String)]
  ): UIO[Either[AuthError, AuthContext]] =
    ZIO
      .attemptBlocking(TokenVerification.verify(processor, token))
      .foldZIO(
        e =>
          TokenVerification.failureOf(e) match {
            case Some((err, detail)) => reject(err, detail)
            case None                => ZIO.die(e)
          },
        claims =>
          TokenVerification.contextOf(claims) match {
            case Left((err, detail)) => reject(err, detail)
            case Right(ctx)          =>
              ZIO.succeed(remember.foreach { case (cache, key) => cache.put(key, ctx) }) *>
                checkDenylist(ctx)
          }
      )

  // `jti` presence is governed by `config.requiredClaims`; keep "jti" there
  // (the default does) so tokens cannot dodge the denylist by omitting it.
  private def checkDenylist(ctx: AuthContext): UIO[Either[AuthError, AuthContext]] =
    Option(ctx.claims.getJWTID) match {
      case None      => accept(ctx)
      case Some(jti) =>
        denylist.isRevoked(jti).either.flatMap {
          case Right(true)  => reject(AuthError.InvalidToken.Revoked, s"jti $jti is denylisted")
          case Right(false) => accept(ctx)
          case Left(e)      =>
            reject(
              AuthError.ValidationUnavailable,
              s"revocation store unavailable: ${e.getMessage}"
            )
        }
    }

  private def accept(ctx: AuthContext): UIO[Either[AuthError, AuthContext]] =
    events.succeeded(ctx).as(Right(ctx))

  private def reject(error: AuthError, detail: String): UIO[Either[AuthError, AuthContext]] =
    events.failed(error, Option(detail).getOrElse("")).as(Left(error))

}
