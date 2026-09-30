package app.http

import cats.effect.{Async, Ref, Resource}
import cats.syntax.all.*
import fs2.io.net.Network

import auth.{AccessTokenAuth, AuthEvents, AuthTelemetry}
import auth.accesstoken.AccessTokenValidator
import auth.dpop.{DpopConfig, DpopJtiStore, DpopNonceValidator, DpopVerifier}
import auth.revocation.{TokenDenylist, TokenIntrospection}
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.middleware.Timeout
import org.http4s.server.Server as Http4sServer
import org.slf4j.LoggerFactory
import app.config.AppConfig
import app.infra.postgres.Database
import org.typelevel.otel4s.trace.Tracer

object Server {

  private val log = LoggerFactory.getLogger(getClass)

  /**
    * @param jtiStore
    *   DPoP proof `jti` single-use store. Default `None` uses a per-node in-memory store — correct
    *   and cheapest for a single node. Behind a load balancer, inject a shared store (see
    *   [[app.MultiNodeMain]]) so a replayed jti is caught on whichever node it lands on.
    * @param nonceOverride
    *   explicit DPoP nonce validator; overrides the config-driven stateless default. Used for the
    *   alternative nonce-anchored replay posture (see [[app.MultiNodeMain]]).
    * @param events
    *   observability sink for every auth decision; compose with
    *   `AuthEvents.combine(AuthEvents.slf4j, otelSink)` for logs + metrics
    * @param telemetry
    *   latency and dependency-health instrumentation for the auth path (validation, denylist,
    *   introspection, JWKS). Defaults to [[auth.AuthTelemetry.noop]]; pass
    *   [[auth.AuthTelemetry.otel]] to record.
    * @param onShed
    *   run for every request [[LoadShedding]] rejects; hook a counter here
    */
  def resource[F[_]: Async: Network: Tracer](
      cfg: AppConfig,
      denylist: TokenDenylist[F],
      events: AuthEvents[F],
      telemetry: AuthTelemetry[F] = AuthTelemetry.noop[F],
      jtiStore: Option[DpopJtiStore[F]] = None,
      nonceOverride: Option[DpopNonceValidator[F]] = None,
      onShed: Option[F[Unit]] = None
  ): Resource[F, Http4sServer] =
    for {
      ds <- Database.pool[F](cfg.db)

      // Flipped on shutdown so /ready fails while the node still serves.
      draining <- Resource.eval(Ref.of[F, Boolean](false))

      // Before anything binds: a node whose schema is behind must not serve.
      _ <- Resource.eval(
             Async[F].whenA(cfg.db.migrateOnStart)(
               Database.migrate[F](ds, cfg.db.baselineOnMigrate)
             )
           )

      // RFC 7662 revocation via the AS (fail closed); owns its pooled client.
      introspection <- cfg.auth.introspection.toIntrospectionConfig match {
                         case None         => Resource.pure[F, Option[TokenIntrospection[F]]](None)
                         case Some(config) =>
                           EmberClientBuilder
                             .default[F]
                             .build
                             .evalMap(TokenIntrospection.http4s[F](config, _))
                             .map(Some(_))
                       }

      // The validator instruments what it is given, so the denylist, the
      // introspection client and Nimbus's JWKS cache are all covered from this
      // one wiring point.
      validator <- AccessTokenValidator
                     .default[F](
                       cfg.auth.toAccessTokenConfig,
                       events,
                       denylist,
                       introspection,
                       telemetry
                     )

      // Stateless (Duende-pattern) nonces: multi-node with a shared key, no
      // store. Without configured key material, fall back to an ephemeral
      // per-process key — fine for one node, useless behind a load balancer.
      // A `nonceOverride` from the composition root takes precedence — used for
      // the alternative nonce-anchored replay posture (a stateful, single-use
      // RedisDpopNonceStore instead of a shared jti set).
      dpopNonceValidator <- nonceOverride match {
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

      dpopVerifier <-
        if (cfg.auth.dpop.enabled)
          // jti single-use anchors DPoP replay defence. `None` -> per-node
          // in-memory (one node sees every request, so that suffices); a
          // multi-node deployment injects a shared store so a replayed jti is
          // rejected on whichever node the load balancer picks.
          DpopVerifier
            .default[F](
              DpopConfig(),
              events,
              dpopNonceValidator = dpopNonceValidator,
              jtiStore = jtiStore
            )
            .map(Some(_))
        else Resource.pure[F, Option[DpopVerifier[F]]](None)

      authMw =
        AccessTokenAuth
          .middleware[F](validator, events, dpopVerifier = dpopVerifier)
      // Shedding is outermost so an overloaded node spends almost nothing on
      // a request it will refuse; the timeout bounds everything beneath it.
      httpApp <- Resource.eval(
                   LoadShedding.httpApp[F](
                     cfg.http.maxInFlight,
                     ServerTracing.DefaultExcludedPaths,
                     onShed.getOrElse(Async[F].unit)
                   )(
                     Timeout.httpApp[F](cfg.http.requestTimeout)(
                       HttpApi
                         .httpApp[F](draining.get.ifM(false.pure[F], Database.ping[F](ds)), authMw)
                     )
                   )
                 )
      server <- EmberServerBuilder
                  .default[F]
                  .withHost(cfg.http.host)
                  .withPort(cfg.http.port)
                  .withHttpApp(httpApp)
                  .withIdleTimeout(cfg.http.idleTimeout)
                  .withShutdownTimeout(cfg.http.shutdownTimeout)
                  .withMaxConnections(cfg.http.maxConnections)
                  .build

      // Acquired last, so released first on SIGTERM — while the server is
      // still accepting. The orchestrator removes a terminating node from the
      // load balancer asynchronously; stopping at once would refuse the
      // requests still being routed here. So: fail readiness, keep serving for
      // `drainDelay` while routing converges, then let the server drain
      // in-flight requests for up to `shutdownTimeout`.
      _ <- Resource.onFinalize(
             Async[F].delay(
               log.info(
                 "Shutdown requested: failing readiness, draining for {}",
                 cfg.http.drainDelay
               )
             ) *> draining.set(true) *> Async[F].sleep(cfg.http.drainDelay)
           )
    } yield server

}
