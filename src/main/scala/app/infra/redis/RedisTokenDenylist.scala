package app.infra.redis

import scala.concurrent.duration.FiniteDuration

import auth.TokenDenylist
import cats.Functor
import cats.syntax.functor.*
import sage.client.internal.Client
import sage.commands.{Commands, SetExpiry}

/** A distributed [[auth.TokenDenylist]] backed by Redis/Valkey via Sage.
  *
  * Optional since [[auth.TokenIntrospection]] exists: introspecting against the
  * authorization server (RFC 7662) gives the same immediate, cluster-wide
  * revocation without any shared store — see `JwtValidator.remote`'s
  * `introspection` parameter. Keep this only if the AS offers no introspection
  * endpoint or its latency is unacceptable even behind the cache.
  *
  * Revocation is shared across every instance of the service — unlike the
  * in-memory Caffeine path, a token revoked on one node is rejected on all of
  * them. A revoked `jti` is stored as a key with a TTL equal to the token's
  * remaining lifetime, so the entry self-evicts once the token would have
  * expired anyway and the denylist never grows without bound.
  *
  * `isRevoked` is a single `EXISTS`, on the hot path of every authenticated
  * request; keep the key small (`prefix + jti`).
  */
final class RedisTokenDenylist[F[_]: Functor](
    client: Client[F, String],
    prefix: String = "revoked:jti:"
) extends TokenDenylist[F] {

  def isRevoked(tokenId: String): F[Boolean] =
    client.run(Commands.exists(prefix + tokenId)).map(_ > 0L)

  /** Revoke a token until it would have expired (`ttl` = `exp - now`). */
  def revoke(tokenId: String, ttl: FiniteDuration): F[Unit] =
    client.run(Commands.set(prefix + tokenId, "1", SetExpiry.In(ttl))).void
}
