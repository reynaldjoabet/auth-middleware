package app.config

import java.net.URI
import java.util.Base64

import scala.concurrent.duration.FiniteDuration

import javax.crypto.SecretKey
import auth.{HttpsUriNoFragment, IssuerUri, NonBlank}
import auth.accesstoken.AccessTokenConfig
import auth.dpop.DpopNonceValidator
import auth.revocation.TokenIntrospection
import com.comcast.ip4s.{Host, Port}
import app.config.given
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*
import io.github.iltotore.iron.pureconfig.given
import org.http4s.Uri
// `_root_.`, because `io.github.iltotore.iron.*` above puts iron's own
// `pureconfig` subpackage in scope under that name — a plain `import
// pureconfig.…` then resolves there and fails. Import order decides which one
// wins, and formatter rules reorder imports, so the prefix is pinned.
import _root_.pureconfig.ConfigReader

final case class AppConfig(
    http: HttpServerConfig,
    db: DbConfig,
    auth: AuthSettings,
    redis: RedisSettings,
    store: StoreSettings,
    revocation: RevocationSettings
) derives ConfigReader

/**
  * Where token revocations come from besides the shared store.
  */
final case class RevocationSettings(kafka: KafkaInvalidationSettings) derives ConfigReader

/**
  * Token invalidations published by the token service on a Kafka topic, applied by every node to a
  * local copy ([[app.infra.kafka.KafkaInvalidations]]). When enabled, revocation checks read that
  * copy instead of the shared store's denylist: no network hop per request, and no per-node
  * revocation cache (`auth.cache.revocation-ttl` is ignored).
  *
  * @param maxTokenLifetime
  *   the longest access-token lifetime the token service issues. On start a node replays the topic
  *   from this long ago, which covers every revocation that can still matter; the topic's retention
  *   must be at least this long.
  * @param maxStaleness
  *   how long the node's copy may go without being confirmed current before revocation checks fail
  *   closed with `503`
  * @param freshnessCheckInterval
  *   how often the node compares what it has applied with the topic's end offsets
  * @param retryBackoff
  *   wait before reconnecting after the consumer fails
  * @param properties
  *   passed to the Kafka client as-is (`"security.protocol"`, `"sasl.jaas.config"`, …). Quote the
  *   keys, or HOCON reads the dots as nesting. Values are [[Secret]]s, so they never show in logs.
  */
final case class KafkaInvalidationSettings(
    enabled: Boolean,
    bootstrapServers: String :| Not[Blank],
    topic: String :| Not[Blank],
    maxTokenLifetime: FiniteDuration,
    maxStaleness: FiniteDuration,
    freshnessCheckInterval: FiniteDuration,
    retryBackoff: FiniteDuration,
    properties: Map[String, Secret]
) derives ConfigReader {

  require(
    freshnessCheckInterval < maxStaleness,
    "revocation.kafka: freshness-check-interval must be shorter than max-staleness, " +
      "or a healthy feed would read as stale between checks"
  )

}

/**
  * Where the shared auth state lives: the revocation denylist, the DPoP proof `jti` set and
  * single-use DPoP nonces.
  *
  * @param backend
  *   `redis` (the `redis` block) or `postgres` (the `db` database, through its own Skunk sessions;
  *   see [[app.infra.postgres.PostgresStores]])
  */
final case class StoreSettings(
    backend: StoreBackend,
    postgres: PostgresStoreSettings
) derives ConfigReader

enum StoreBackend derives CanEqual {
  case Redis, Postgres
}

object StoreBackend {

  // Plain strings in the config (`backend = postgres`), hence the enumeration form.
  given ConfigReader[StoreBackend] =
    _root_.pureconfig.generic.semiauto.deriveEnumerationReader

}

/**
  * The Postgres store's sessions; connection details come from `db`.
  *
  * @param sessions
  *   connections held open for the stores, separate from the HikariCP pool. Each runs one statement
  *   at a time, so this caps concurrent store round trips per node.
  * @param commandTimeout
  *   upper bound on one store call, waiting for a session included; past it the request fails
  *   closed with `503`. Also sent as the sessions' `statement_timeout`, so Postgres abandons the
  *   statement too.
  * @param synchronousCommit
  *   `false` acknowledges a write before its WAL record reaches disk. A crash can then lose the
  *   last few hundred milliseconds of spent `jti`s and nonces; it cannot corrupt anything.
  * @param maxBatch
  *   calls of one kind answered by a single statement at most (see [[app.infra.postgres.Batcher]]);
  *   `1` turns batching off
  * @param sweepInterval
  *   how often expired rows are deleted (each node sweeps; `SKIP LOCKED` keeps them apart)
  * @param sweepBatch
  *   rows deleted per statement while sweeping, so no sweep holds locks for long
  */
final case class PostgresStoreSettings(
    sessions: Int :| Positive,
    commandTimeout: FiniteDuration,
    synchronousCommit: Boolean,
    maxBatch: Int :| Positive,
    sweepInterval: FiniteDuration,
    sweepBatch: Int :| Positive
) derives ConfigReader

/**
  * Ember server binding and back-pressure knobs.
  *
  * @param maxInFlight
  *   requests handled concurrently before the excess is shed with `503` (see
  *   [[app.http.LoadShedding]])
  * @param requestTimeout
  *   upper bound on producing one response; past it the client gets `503` and the work is cancelled
  * @param drainDelay
  *   on shutdown, how long the node keeps serving with readiness failing before it stops accepting
  *   — time for the load balancer to stop routing here. `drainDelay + shutdownTimeout` must stay
  *   below the platform's termination grace period.
  */
final case class HttpServerConfig(
    host: Host,
    port: Port,
    idleTimeout: FiniteDuration,
    shutdownTimeout: FiniteDuration,
    maxConnections: Int,
    maxInFlight: Int :| Positive,
    requestTimeout: FiniteDuration,
    drainDelay: FiniteDuration
) derives ConfigReader

/**
  * Database connection + HikariCP pool tuning. The password is a [[Secret]] so the whole case class
  * is safe to log.
  *
  * @param migrateOnStart
  *   apply pending Flyway migrations during boot, before the server binds. Turn it off where
  *   migrations are a separate deploy step (a k8s Job, a DBA gate); the app then assumes the schema
  *   is already current.
  * @param baselineOnMigrate
  *   see [[app.infra.postgres.Database.migrate]] — a one-shot switch for adopting Flyway on a
  *   database that already has the schema.
  */
final case class DbConfig(
    host: String,
    port: Int :| Interval.Closed[1, 65535],
    name: String,
    user: String,
    password: Secret,
    maxPoolSize: Int,
    connectTimeout: FiniteDuration,
    maxLifetime: FiniteDuration,
    leakDetectionThreshold: FiniteDuration,
    migrateOnStart: Boolean,
    baselineOnMigrate: Boolean
) derives ConfigReader {
  def jdbcUrl: String = s"jdbc:postgresql://$host:$port/$name"
}

final case class AuthSettings(
    issuer: String :| IssuerUri,
    audience: String :| NonBlank,
    jwksUri: String :| HttpsUriNoFragment,
    dpop: DpopSettings,
    introspection: IntrospectionSettings,
    cache: AuthCacheSettings,
    mtlsForwardedCertHeader: Option[String :| NonBlank]
) derives ConfigReader {

  def toAccessTokenConfig: AccessTokenConfig =
    AccessTokenConfig(
      issuer,
      audience,
      URI.create(jwksUri),
      verifiedTokenCacheMaxEntries = cache.verifiedTokens,
      verifiedTokenCacheMaxTtl = cache.verifiedTokenTtl,
      revocationCacheTtl = cache.revocationTtl
    )

}

/**
  * Hot-path caches; see [[auth.accesstoken.AccessTokenConfig]] for the semantics of each.
  *
  * @param verifiedTokens
  *   verified tokens remembered per node (`0` disables); skips signature checks on reuse
  * @param verifiedTokenTtl
  *   cap on reusing one verification, whatever the token's `exp`
  * @param revocationTtl
  *   how long a node reuses a denylist answer — the worst-case revocation delay it adds (`0`
  *   disables)
  */
final case class AuthCacheSettings(
    verifiedTokens: Long :| GreaterEqual[0L],
    verifiedTokenTtl: FiniteDuration,
    revocationTtl: FiniteDuration
) derives ConfigReader

/**
  * RFC 9449 DPoP sender-constrained tokens. When enabled, the middleware accepts the `DPoP` scheme
  * and verifies proofs; `nonce` additionally requires server-provided nonces on every proof (the
  * FAPI 2.0 replay fix).
  */
final case class DpopSettings(
    enabled: Boolean,
    nonce: DpopNonceSettings
) derives ConfigReader

/**
  * Stateless (Duende-pattern) nonce keys: base64-encoded AES key material (16/24/32 bytes) shared
  * by every node via the secret manager, held as [[Secret]] so it can never leak through a logged
  * config. `key` absent → an ephemeral per-process key is generated at boot (single-node/dev only;
  * logged loudly). `previousKeys` keeps in-flight nonces valid during key rotation.
  */
final case class DpopNonceSettings(
    enabled: Boolean,
    mode: DpopNonceMode,
    key: Option[Secret],
    previousKeys: List[Secret],
    lifetime: FiniteDuration
) derives ConfigReader {

  def decodedKey: Option[SecretKey] = key.map(decode)

  def decodedPreviousKeys: List[SecretKey] = previousKeys.map(decode)

  private def decode(base64: Secret): SecretKey =
    DpopNonceValidator.keyFromBytes(Base64.getDecoder.decode(base64.value))

}

/**
  * Where DPoP replay-defence state lives in a multi-node deployment ([[app.MultiNodeMain]]).
  *
  *   - `Stateless`: nonces are AES-GCM-sealed timestamps any node can check with the shared key,
  *     reusable within their lifetime; replay is anchored by a shared Redis set of spent proof
  *     `jti`s. One Redis write per DPoP request.
  *   - `Redis`: nonces are single-use Redis entries, consumed on use and minted for every response;
  *     a replayed proof carries an already-consumed nonce, so no shared `jti` set is needed. Two
  *     Redis round trips per DPoP request, and a client can have only one request in flight per
  *     nonce.
  */
enum DpopNonceMode derives CanEqual {
  case Stateless, Redis
}

object DpopNonceMode {

  // Plain strings in the config (`mode = stateless`), hence the enumeration form.
  given ConfigReader[DpopNonceMode] =
    _root_.pureconfig.generic.semiauto.deriveEnumerationReader

}

/**
  * RFC 7662 revocation checking against the AS — the Redis-free alternative to a distributed
  * denylist. Endpoint and client credentials are required when enabled; the boot fails otherwise.
  */
final case class IntrospectionSettings(
    enabled: Boolean,
    endpoint: Option[String :| HttpsUriNoFragment],
    clientId: Option[String :| NonBlank],
    clientSecret: Option[Secret],
    cacheTtl: FiniteDuration,
    requestTimeout: FiniteDuration
) derives ConfigReader {

  def toIntrospectionConfig: Option[TokenIntrospection.IntrospectionConfig] =
    Option.when(enabled) {
      def required[A](field: Option[A], name: String): A =
        field.getOrElse(
          throw new IllegalArgumentException(
            s"auth.introspection.$name is required when introspection is enabled"
          )
        )
      TokenIntrospection.IntrospectionConfig(
        endpoint = Uri.unsafeFromString(required(endpoint, "endpoint")),
        clientId = required(clientId, "client-id"),
        clientSecret = required(clientSecret, "client-secret").value,
        cacheTtl = cacheTtl,
        requestTimeout = requestTimeout
      )
    }

}
