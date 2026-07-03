package app.http

import auth.dpop.{DpopConfig, DpopNonceValidator, DpopVerifier}
import auth.revocation.{TokenDenylist, TokenIntrospection}
import auth.{AuthEvents, BearerAuth, JwtValidator}
import cats.effect.{Async, Resource}
import cats.syntax.all.*
import fs2.io.net.Network
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.Server as Http4sServer
import org.slf4j.LoggerFactory
import app.config.AppConfig
import app.infra.postgres.Database

object Server {

  private val log = LoggerFactory.getLogger(getClass)

  def resource[F[_]: Async: Network](
      cfg: AppConfig,
      denylist: TokenDenylist[F]
  ): Resource[F, Http4sServer] =
    for {
      ds <- Database.pool[F](cfg.db)
      events = AuthEvents.slf4j[F]

      // RFC 7662 revocation via the AS (fail closed); owns its pooled client.
      introspection <- cfg.auth.introspection.toIntrospectionConfig match {
        case None => Resource.pure[F, Option[TokenIntrospection[F]]](None)
        case Some(config) =>
          EmberClientBuilder
            .default[F]
            .build
            .evalMap(TokenIntrospection.http4s[F](config, _))
            .map(Some(_))
      }

      validator <- Resource.eval(
        JwtValidator
          .remote[F](cfg.auth.toAuthConfig, events, denylist, introspection)
      )

      // Stateless (Duende-pattern) nonces: multi-node with a shared key, no
      // store. Without configured key material, fall back to an ephemeral
      // per-process key — fine for one node, useless behind a load balancer.
      nonces <-
        if (cfg.auth.dpop.enabled && cfg.auth.dpop.nonce.enabled)
          Resource.eval(
            (cfg.auth.dpop.nonce.decodedKey match {
              case Some(key) => key.pure[F]
              case None      =>
                Async[F].delay(
                  log.warn(
                    "No dpop.nonce.key configured — using an ephemeral key. " +
                      "Nonces will not validate across nodes or restarts; " +
                      "set DPOP_NONCE_KEY in production."
                  )
                ) *> DpopNonceValidator.randomKey[F]
            }).flatMap(key =>
              DpopNonceValidator.stateless[F](
                key,
                cfg.auth.dpop.nonce.decodedPreviousKeys,
                cfg.auth.dpop.nonce.lifetime
              )
            ).map(Some(_))
          )
        else Resource.pure[F, Option[DpopNonceValidator[F]]](None)

      dpop <-
        if (cfg.auth.dpop.enabled)
          DpopVerifier
            .default[F](DpopConfig(), events, nonces = nonces)
            .map(Some(_))
        else Resource.pure[F, Option[DpopVerifier[F]]](None)

      authMw = BearerAuth.middleware[F](validator, events, dpop = dpop)
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
