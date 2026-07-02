package app.http

import auth.{AuthEvents, BearerAuth, JwtValidator, TokenDenylist}
import cats.effect.{Async, Resource}
import fs2.io.net.Network
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.Server as Http4sServer
import app.config.AppConfig
import app.infra.postgres.Database

object Server {

  def resource[F[_]: Async: Network](
      cfg: AppConfig,
      denylist: TokenDenylist[F]
  ): Resource[F, Http4sServer] =
    for {
      ds <- Database.pool[F](cfg.db)
      events = AuthEvents.slf4j[F]
      validator <- Resource.eval(
        JwtValidator.remote[F](cfg.auth.toAuthConfig, events, denylist)
      )
      authMw = BearerAuth.middleware[F](validator, events)
      httpApp = HttpApi.httpApp[F](ds, authMw)
      server <- EmberServerBuilder
        .default[F]
        .withHost(cfg.http.host)
        .withPort(cfg.http.port)
        .withHttpApp(httpApp)
        .withIdleTimeout(cfg.http.idleTimeout)
        .withShutdownTimeout(cfg.http.shutdownTimeout)
        .withMaxConnections(cfg.http.maxConnections)
        .build
    } yield server
}
