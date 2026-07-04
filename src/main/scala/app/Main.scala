package app

import auth.AuthEvents
import cats.effect.{IO, IOApp, Resource}
import cats.effect.unsafe.IORuntimeConfig
import org.http4s.server.Server as Http4sServer
import org.slf4j.LoggerFactory
import org.typelevel.otel4s.oteljava.OtelJava
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
      // GlobalOpenTelemetry, autoconfigured via the
      // -Dotel.java.global-autoconfigure.enabled=true javaOption; noop when no
      // exporter is configured, so local runs cost nothing.
      otel <- Resource.eval(OtelJava.global[IO])
      meter <- Resource.eval(otel.meterProvider.get("auth-middleware"))
      otelEvents <- Resource.eval(AuthEvents.otel[IO](meter))
      events = AuthEvents.combine(AuthEvents.slf4j[IO], otelEvents)
      // No jti/nonce override: single node uses the in-memory jti checker and
      // config-driven stateless nonces. Redis here backs only revocation.
      server <- Server.resource[IO](cfg, denylist, events)
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
