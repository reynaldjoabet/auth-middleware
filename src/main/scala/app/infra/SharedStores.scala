package app.infra

import scala.concurrent.duration.FiniteDuration

import cats.effect.{IO, Resource}

import auth.dpop.{DpopJtiStore, DpopNonceStore}
import auth.revocation.TokenDenylist
import sage.backend.SageClient
import app.config.{AppConfig, StoreBackend}
import app.infra.postgres.PostgresStores
import app.infra.redis.{RedisDpopJtiStore, RedisDpopNonceStore, RedisTokenDenylist}

/**
  * The auth state every node must share, from whichever backend `app.store.backend` names.
  *
  * @param nonces
  *   single-use DPoP nonces, given their lifetime; used only in nonce mode `redis`, whatever the
  *   backend (the mode name predates the Postgres backend)
  */
final case class SharedStores[F[_]](
    denylist: TokenDenylist[F],
    jtis: DpopJtiStore[F],
    nonces: FiniteDuration => DpopNonceStore[F]
)

object SharedStores {

  def resource(cfg: AppConfig): Resource[IO, SharedStores[IO]] =
    cfg.store.backend match {
      case StoreBackend.Redis =>
        val timeout = cfg.redis.commandTimeout
        SageClient.resource(cfg.redis.toSageConfig).map { redis =>
          SharedStores[IO](
            RedisTokenDenylist[IO](redis, timeout),
            RedisDpopJtiStore[IO](redis, timeout),
            ttl => new RedisDpopNonceStore[IO](redis, timeout, ttl)
          )
        }
      case StoreBackend.Postgres =>
        PostgresStores.resource[IO](cfg.db, cfg.store.postgres)
    }

}
