package app

import cats.effect.{IO, IOApp, Resource}
import cats.effect.unsafe.IORuntimeConfig
import org.http4s.server.Server as Http4sServer
import org.slf4j.LoggerFactory
import sage.backend.SageClient
import scala.concurrent.duration.*
import app.config.{AppConfigLoader, AppConfig}
import app.http.Server
import app.infra.redis.RedisTokenDenylist
object Main extends IOApp.Simple {

  private val log = LoggerFactory.getLogger(getClass)

  override protected def runtimeConfig: IORuntimeConfig =
    super.runtimeConfig.copy(cpuStarvationCheckInterval = 10.seconds)

  // The whole app as one Resource: Redis client → DB pool → token validator →
  // Ember, released in reverse on SIGTERM.
  private def app(cfg: AppConfig): Resource[IO, Http4sServer] =
    for {
      redis <- SageClient.resource(cfg.redis.toSageConfig)
      denylist = RedisTokenDenylist[IO](redis)
      server <- Server.resource[IO](cfg, denylist)
    } yield server

  val run: IO[Unit] =
    AppConfigLoader.load[IO].flatMap { cfg =>
      // Never log cfg.db directly — password is a plain String and would leak.
      IO(
        log.info(
          "Configuration loaded: http={}, db={}",
          cfg.http,
          cfg.db.jdbcUrl
        )
      ) *>
        app(cfg).use { server =>
          IO(log.info("Server listening on {}", server.address)) *> IO.never
        }
    }
}
