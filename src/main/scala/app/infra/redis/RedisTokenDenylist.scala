package app.infra.redis

import scala.concurrent.duration.FiniteDuration

import cats.effect.syntax.temporal.*
import cats.effect.Temporal
import cats.syntax.functor.*

import auth.revocation.TokenDenylist
import sage.client.internal.Client
import sage.commands.{Commands, SetExpiry}

/**
  * A distributed [[auth.revocation.TokenDenylist]] backed by Redis/Valkey via Sage.
  *
  * Optional since [[auth.revocation.TokenIntrospection]] exists: introspecting against the
  * authorization server (RFC 7662) gives the same immediate, cluster-wide revocation without any
  * shared store — see `AccessTokenValidator.default`'s `introspection` parameter. Keep this only if
  * the AS offers no introspection endpoint or its latency is unacceptable even behind the cache.
  *
  * Revocation is shared across every instance of the service — unlike the in-memory Caffeine path,
  * a token revoked on one node is rejected on all of them. A revoked `jti` is stored as a key with
  * a TTL equal to the token's remaining lifetime, so the entry self-evicts once the token would
  * have expired anyway and the denylist never grows without bound.
  *
  * `isRevoked` is a single `EXISTS`, on the hot path of every authenticated request; keep the key
  * small (`prefix + jti`). It is bounded by `timeout`, so a stalled Redis raises instead of hanging
  * the request, and the validator fails closed with `503`. Front it with
  * [[auth.revocation.TokenDenylist.cached]] to take most reads off Redis.
  */
final class RedisTokenDenylist[F[_]: Temporal](
    client: Client[F, String],
    timeout: FiniteDuration,
    prefix: String = "revoked:jti:"
) extends TokenDenylist[F] {

  def isRevoked(tokenId: String): F[Boolean] =
    client.run(Commands.exists(prefix + tokenId)).map(_ > 0L).timeout(timeout)

  /**
    * Revoke a token until it would have expired (`ttl` = `exp - now`).
    */
  def revoke(tokenId: String, ttl: FiniteDuration): F[Unit] =
    client.run(Commands.set(prefix + tokenId, "1", SetExpiry.In(ttl))).void.timeout(timeout)

}
