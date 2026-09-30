package app

import scala.concurrent.duration.*

import cats.effect.{IO, IOApp, Resource}
import cats.effect.unsafe.IORuntimeConfig

import auth.{AuthEvents, AuthTelemetry}
import auth.dpop.DpopNonceValidator
import org.http4s.server.Server as Http4sServer
import org.slf4j.LoggerFactory
import org.typelevel.otel4s.oteljava.OtelJava
import org.typelevel.otel4s.trace.Tracer
import sage.backend.SageClient
import app.config.{AppConfig, AppConfigLoader, DpopNonceMode}
import app.http.Server
import app.infra.redis.{RedisDpopJtiStore, RedisDpopNonceStore, RedisTokenDenylist}

/**
  * Composition root for a **multi-node, load-balanced** deployment (the FAPI 2.0 production
  * posture) — the counterpart to [[Main]].
  *
  * ==Why a second entrypoint==
  *
  * The app tier is deliberately stateless so it scales horizontally: any node must serve any
  * request. That only holds if every piece of *security-relevant state* lives in a store shared by
  * all nodes. The single difference from [[Main]] is therefore not new logic — it is *where the
  * replay-defence state lives*. Below, everything tagged `[SHARED]` is moved off-heap into
  * Redis/Valkey. A `dpop.nonce.key` shared by all nodes is required for the stateless nonces to
  * validate across the cluster (an ephemeral per-process key works single-node but not here —
  * [[Server]] logs loudly if it is missing).
  *
  * ==Replay defence: the two moving parts==
  *
  *   - '''`jti` single-use''' is the anchor. Each DPoP proof carries a unique `jti`; accepting a
  *     proof "spends" it, and a repeat is a replay. This is the primary RFC 9449 §11.1 replay
  *     mitigation. It is *stateful by necessity* — you cannot detect "seen before" without
  *     remembering — so on one node an in-memory set works, but across nodes the set MUST be
  *     shared, or a load balancer defeats it by sending the replay to a node that never saw the
  *     `jti`. Hence `[SHARED]` Redis here.
  *   - '''nonce (RFC 9449 §8)''' is a *freshness* signal, not the single-use anchor. This
  *     deployment uses **stateless** (Duende-pattern) nonces: an HMAC over a timestamp under a key
  *     shared by all nodes. Any node validates any node's nonce with no store — so nonces need only
  *     a shared *key*, not a shared *store*. They prove the proof was minted recently (tighter than
  *     client `iat`, and independent of client clocks) and stop pre-computed proofs; they do not,
  *     by themselves, stop an in-window replay — the shared `jti` store does that.
  *
  * That division is the answer to "if nonces are stateless, why Redis at all?": the Redis
  * dependency is for the `jti` single-use set, not for nonces. (The alternative posture — a
  * *stateful, single-use* nonce store as the anchor instead of `jti` tracking, see
  * [[app.infra.redis.RedisDpopNonceStore]] — is selected with `auth.dpop.nonce.mode = redis`. It
  * replaces the shared `jti` store rather than adding to it, so neither mode pays for both.)
  *
  * ==Request flow==
  *
  * {{{
  *   Client  --DPoP/Bearer-->  [ Load Balancer ]  -->  any of N stateless app nodes
  *
  *                               request -> Node_i
  *                                   |
  *   +---------------------- AccessTokenAuth.middleware -----------------------+
  *   | AUTHENTICATE  (is the credential + sender genuine?)                |
  *   |   1. extractCredentials    Bearer | DPoP; reject ?access_token=    |
  *   |   2. AccessTokenValidator.validate  sig,iss,aud,exp,typ,required     ------+--> AS /jwks       (cached per node)
  *   |        - revocation denylist                                 ------+--> Redis EXISTS revoked:jti     [SHARED]
  *   |        - introspection (opaque tokens, RFC 7662)             ------+--> AS /introspect
  *   |   3. DpopVerifier.verify    htu,htm,iat,ath,cnf.jkt                |
  *   |        - nonce: HMAC verify with shared key (no store) -----------> [SHARED KEY]
  *   |        - jti single-use                                      ------+--> Redis SET NX  dpop:jti:*     [SHARED]
  *   |   4. mTLS cnf.x5t#S256 (proof of possession)                       |
  *   | AUTHORIZE  (may this genuine principal do this?)                   |
  *   |   5. requireScopes / requireAcr / requireUser / requireFreshAuth   |
  *   +--------------------------------+----------------------------------+
  *                                    |
  *                                    v
  *                               route handler  -->  Postgres (app data)
  * }}}
  *
  * ==What each shared piece is, and why==
  *
  *   - '''Redis/Valkey (Sage client)''' — one client reused for all shared auth state, keeping
  *     pools and the failure domain in one place.
  *   - '''RedisTokenDenylist''' `[SHARED]` — RS-side revocation. A token revoked on one node
  *     (compromise, off-boarding, fraud hold) is rejected on all of them at once, not after it
  *     expires. Hot path: one `EXISTS`.
  *   - '''RedisDpopJtiStore''' `[SHARED]` — cluster-wide single-use of the proof `jti` via atomic
  *     `SET NX`. This is what makes DPoP replay defence hold behind a load balancer.
  *   - '''Stateless nonce (shared key)''' `[SHARED KEY]` — freshness only, wired in [[Server]] from
  *     `dpop.nonce.key`. No store, hence no per-proof Redis round trip; the key must be the same on
  *     every node.
  *   - '''Postgres (HikariCP)''' — application data, pooled per node; part of the same lifecycle so
  *     it is released on shutdown.
  *   - '''OpenTelemetry `AuthEvents`''' — `auth.decisions` / `auth.challenges` counters alongside
  *     logs; a fleet needs the aggregate to see cluster-wide abuse that per-node logs hide.
  *
  * The whole app is one [[cats.effect.Resource]]: Redis -> DB pool -> validator -> Ember server,
  * acquired at start and released in reverse on SIGTERM.
  */
object MultiNodeMain extends IOApp.Simple {

  private val log = LoggerFactory.getLogger(getClass)

  protected override def runtimeConfig: IORuntimeConfig =
    super.runtimeConfig.copy(cpuStarvationCheckInterval = 10.seconds)

  private def app(cfg: AppConfig): Resource[IO, Http4sServer] =
    for {
      // One shared Redis/Valkey client, reused for every distributed store.
      redis <- SageClient.resource(cfg.redis.toSageConfig)

      // Distributed revocation: reject a revoked jti on every node at once.
      denylist = RedisTokenDenylist[IO](redis, cfg.redis.commandTimeout)

      // Replay defence, per `auth.dpop.nonce.mode` (only when DPoP is on):
      //   stateless — shared-key nonces (built by Server) + a shared Redis set
      //               of spent proof jtis: the cross-node replay anchor.
      //   redis     — single-use nonces in Redis: a replayed proof carries a
      //               consumed nonce, so the per-node jti set suffices.
      dpopDisabled = !cfg.auth.dpop.enabled
      redisNonces  = cfg.auth.dpop.nonce.enabled &&
                      cfg.auth.dpop.nonce.mode == DpopNonceMode.Redis
      jtiStore = Option.when(!dpopDisabled && !redisNonces)(
                   RedisDpopJtiStore[IO](redis, cfg.redis.commandTimeout)
                 )
      nonceOverride = Option.when(!dpopDisabled && redisNonces)(
                        DpopNonceValidator.fromStore[IO](
                          new RedisDpopNonceStore[IO](
                            redis,
                            cfg.redis.commandTimeout,
                            cfg.auth.dpop.nonce.lifetime
                          )
                        )
                      )

      // Logs + OpenTelemetry metrics and traces. autoconfigure is a no-op with
      // no exporter.
      otel             <- Resource.eval(OtelJava.global[IO])
      meter            <- Resource.eval(otel.meterProvider.get("auth-middleware"))
      given Tracer[IO] <- Resource.eval(
                            otel.tracerProvider.get("auth-middleware")
                          )
      otelEvents <- Resource.eval(AuthEvents.otel[IO](meter))
      events      = AuthEvents.combine(AuthEvents.slf4j[IO](), otelEvents)

      // Per-dependency latency, which matters more here than on one node: with
      // the denylist and the jti set both in Redis, "the cluster is slow" and
      // "Redis is slow" are the same picture until something separates them.
      telemetry <- AuthTelemetry.otel[IO](meter)
      shed      <- Resource.eval(
                meter
                  .counter[Long]("http.server.shed")
                  .withDescription("Requests rejected 503 by load shedding")
                  .create
              )

      server <- Server.resource[IO](
                  cfg,
                  denylist,
                  events,
                  telemetry,
                  jtiStore = jtiStore,
                  nonceOverride = nonceOverride,
                  onShed = Some(shed.inc())
                )
    } yield server

  val run: IO[Unit] =
    // Before anything can log: scribe is configured in code, not by a file on
    // the classpath, so an unconfigured logger would silently use defaults.
    IO(Logging.configure()) *> AppConfigLoader.load[IO].flatMap { cfg =>
      // Secrets are `Secret`s with a redacted toString, so logging config
      // values here cannot leak them. Config invariants (e.g. redis.nodes
      // non-empty) are enforced at load time by the settings themselves, so a
      // bad config fails before we get here.
      IO(
        log.info(
          "Multi-node start: http={}, db={}, redis={} node(s)",
          cfg.http,
          cfg.db.jdbcUrl,
          cfg.redis.nodes.size
        )
      ) *>
        app(cfg).use { server =>
          IO(log.info("Server listening on {}", server.address)) *> IO.never
        }
    }

}
