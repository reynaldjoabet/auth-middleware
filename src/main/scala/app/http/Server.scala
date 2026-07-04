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
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProofUse
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker

object Server {

  private val log = LoggerFactory.getLogger(getClass)

  /** @param singleUseChecker
    *   DPoP proof `jti` single-use checker. Default `None` uses Nimbus's
    *   per-node in-memory checker — correct and cheapest for a single node.
    *   Behind a load balancer, inject a shared-store checker (see
    *   [[app.MultiNodeMain]]) so a replayed jti is caught on whichever node it
    *   lands on.
    * @param nonceOverride
    *   explicit DPoP nonce validator; overrides the config-driven stateless
    *   default. Used for the alternative nonce-anchored replay posture (see
    *   [[app.MultiNodeMain]]).
    * @param events
    *   observability sink for every auth decision; compose with
    *   `AuthEvents.combine(AuthEvents.slf4j, otelSink)` for logs + metrics
    */
  def resource[F[_]: Async: Network](
      cfg: AppConfig,
      denylist: TokenDenylist[F],
      events: AuthEvents[F],
      singleUseChecker: Option[SingleUseChecker[DPoPProofUse]] = None,
      nonceOverride: Option[DpopNonceValidator[F]] = None
  ): Resource[F, Http4sServer] =
    for {
      ds <- Database.pool[F](cfg.db)

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
      // A `nonceOverride` from the composition root (e.g. the strict,
      // cluster-wide single-use RedisDpopNonceStore in MultiNodeMain) takes
      // precedence over this config-driven default.
      nonces <- nonceOverride match {
        case injected @ Some(_) =>
          Resource.pure[F, Option[DpopNonceValidator[F]]](injected)
        case None =>
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
      }

      dpop <-
        if (cfg.auth.dpop.enabled)
          // jti single-use anchors DPoP replay defence. `None` -> per-node
          // in-memory (one node sees every request, so that suffices); a
          // multi-node deployment injects a shared-store checker so a replayed
          // jti is rejected on whichever node the load balancer picks.
          DpopVerifier
            .default[F](
              DpopConfig(),
              events,
              nonces = nonces,
              singleUseChecker = singleUseChecker
            )
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
