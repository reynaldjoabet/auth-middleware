package app

import scala.concurrent.duration.*

import auth.AuthEvents
import cats.effect.unsafe.IORuntimeConfig
import cats.effect.{IO, IOApp, Resource}
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProofUse
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker
import org.http4s.server.Server as Http4sServer
import org.slf4j.LoggerFactory
import org.typelevel.otel4s.oteljava.OtelJava
import sage.backend.SageClient

import app.config.{AppConfig, AppConfigLoader}
import app.http.Server
import app.infra.redis.{RedisDpopSingleUseChecker, RedisTokenDenylist}

/** Composition root for a **multi-node, load-balanced** deployment (the FAPI
  * 2.0 production posture) — the counterpart to [[Main]].
  *
  * ==Why a second entrypoint==
  *
  * The app tier is deliberately stateless so it scales horizontally: any node
  * must serve any request. That only holds if every piece of *security-relevant
  * state* lives in a store shared by all nodes. The single difference from
  * [[Main]] is therefore not new logic — it is *where the replay-defence state
  * lives*. Below, everything tagged `[SHARED]` is moved off-heap into
  * Redis/Valkey. A `dpop.nonce.key` shared by all nodes is required for the
  * stateless nonces to validate across the cluster (an ephemeral per-process
  * key works single-node but not here — [[Server]] logs loudly if it is
  * missing).
  *
  * ==Replay defence: the two moving parts==
  *
  *   - '''`jti` single-use''' is the anchor. Each DPoP proof carries a unique
  *     `jti`; accepting a proof "spends" it, and a repeat is a replay. This is
  *     the primary RFC 9449 §11.1 replay mitigation. It is *stateful by
  *     necessity* — you cannot detect "seen before" without remembering — so on
  *     one node an in-memory set works, but across nodes the set MUST be
  *     shared, or a load balancer defeats it by sending the replay to a node
  *     that never saw the `jti`. Hence `[SHARED]` Redis here.
  *   - '''nonce (RFC 9449 §8)''' is a *freshness* signal, not the single-use
  *     anchor. This deployment uses **stateless** (Duende-pattern) nonces: an
  *     HMAC over a timestamp under a key shared by all nodes. Any node
  *     validates any node's nonce with no store — so nonces need only a shared
  *     *key*, not a shared *store*. They prove the proof was minted recently
  *     (tighter than client `iat`, and independent of client clocks) and stop
  *     pre-computed proofs; they do not, by themselves, stop an in-window
  *     replay — the shared `jti` store does that.
  *
  * That division is the answer to "if nonces are stateless, why Redis at all?":
  * the Redis dependency is for the `jti` single-use set, not for nonces. (The
  * alternative posture — using a *stateful, single-use* nonce store as the
  * anchor instead of `jti` tracking — is described under
  * [[app.infra.redis.RedisDpopNonceStore]]; inject it via `Server`'s
  * `nonceOverride`. It is an alternative to the shared `jti` store, not an
  * addition, so this default does not pay for both.)
  *
  * ==Request flow==
  *
  * {{{
  *   Client  --DPoP/Bearer-->  [ Load Balancer ]  -->  any of N stateless app nodes
  *
  *                               request -> Node_i
  *                                   |
  *   +---------------------- BearerAuth.middleware -----------------------+
  *   | AUTHENTICATE  (is the credential + sender genuine?)                |
  *   |   1. extractCredentials    Bearer | DPoP; reject ?access_token=    |
  *   |   2. JwtValidator.validate  sig,iss,aud,exp,typ,required     ------+--> AS /jwks       (cached per node)
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
  *   - '''Redis/Valkey (Sage client)''' — one client reused for all shared auth
  *     state, keeping pools and the failure domain in one place.
  *   - '''RedisTokenDenylist''' `[SHARED]` — RS-side revocation. A token
  *     revoked on one node (compromise, off-boarding, fraud hold) is rejected
  *     on all of them at once, not after it expires. Hot path: one `EXISTS`.
  *   - '''RedisDpopSingleUseChecker''' `[SHARED]` — cluster-wide single-use of
  *     the proof `jti` via atomic `SET NX`. This is what makes DPoP replay
  *     defence hold behind a load balancer.
  *   - '''Stateless nonce (shared key)''' `[SHARED KEY]` — freshness only,
  *     wired in [[Server]] from `dpop.nonce.key`. No store, hence no per-proof
  *     Redis round trip; the key must be the same on every node.
  *   - '''Postgres (HikariCP)''' — application data, pooled per node; part of
  *     the same lifecycle so it is released on shutdown.
  *   - '''OpenTelemetry `AuthEvents`''' — `auth.decisions` / `auth.challenges`
  *     counters alongside logs; a fleet needs the aggregate to see cluster-wide
  *     abuse that per-node logs hide.
  *
  * The whole app is one [[cats.effect.Resource]]: Redis -> DB pool -> validator
  * -> Ember server, acquired at start and released in reverse on SIGTERM.
  */
object MultiNodeMain extends IOApp.Simple {

  private val log = LoggerFactory.getLogger(getClass)

  override protected def runtimeConfig: IORuntimeConfig =
    super.runtimeConfig.copy(cpuStarvationCheckInterval = 10.seconds)

  private def app(cfg: AppConfig): Resource[IO, Http4sServer] =
    for {
      // One shared Redis/Valkey client, reused for every distributed store.
      redis <- SageClient.resource(cfg.redis.toSageConfig)

      // Distributed revocation: reject a revoked jti on every node at once.
      denylist = RedisTokenDenylist[IO](redis)

      // The cross-node replay anchor: a shared, single-use jti set. Only when
      // DPoP is on — otherwise there is nothing to check and no Dispatcher to
      // spin up. Nonces stay stateless (Server builds them from the shared key).
      jtiChecker <-
        if (cfg.auth.dpop.enabled)
          RedisDpopSingleUseChecker.resource[IO](redis).map(Some(_))
        else
          Resource.pure[IO, Option[SingleUseChecker[DPoPProofUse]]](None)

      // Logs + OpenTelemetry metrics. autoconfigure is a no-op with no exporter.
      otel <- Resource.eval(OtelJava.global[IO])
      meter <- Resource.eval(otel.meterProvider.get("auth-middleware"))
      otelEvents <- Resource.eval(AuthEvents.otel[IO](meter))
      events = AuthEvents.combine(AuthEvents.slf4j[IO], otelEvents)

      server <- Server.resource[IO](
        cfg,
        denylist,
        events,
        singleUseChecker = jtiChecker
      )
    } yield server

  val run: IO[Unit] =
    AppConfigLoader.load[IO].flatMap { cfg =>
      // Never log cfg.db directly — the password is a plain String. Config
      // invariants (e.g. redis.nodes non-empty) are enforced at load time by
      // the settings themselves, so a bad config fails before we get here.
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
