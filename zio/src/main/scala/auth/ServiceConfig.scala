package auth

import java.net.URI

import scala.concurrent.duration.{FiniteDuration, NANOSECONDS}

import auth.accesstoken.AccessTokenConfig
import com.typesafe.config.ConfigFactory
import io.github.iltotore.iron.*
import sage.client.{
  AuthConfig as SageAuth,
  Endpoint,
  SageConfig,
  TlsConfig,
  Topology,
  TrustSource,
  WatchdogConfig
}
import scribe.Level
import zio.{Chunk, Config, IO, ZIO}
import zio.config.typesafe.TypesafeConfigProvider

/**
  * The ZIO service's configuration: the `app` tree of `application.conf` (environment overrides
  * included), read with zio-config into plain case classes. Each field is described by hand in the
  * companion objects, so every key, default and validation rule is visible here and nothing is
  * derived from field names.
  *
  * A value that fails validation fails the boot with the full key path in the message.
  */
final case class ServiceConfig(
    logLevel: Level,
    http: HttpSettings,
    auth: AuthSettings,
    redis: RedisSettings
)

object ServiceConfig {

  val descriptor: Config[ServiceConfig] =
    (level("log-level") ++
      HttpSettings.descriptor.nested("http") ++
      AuthSettings.descriptor.nested("auth") ++
      RedisSettings.descriptor.nested("redis"))
      .map(ServiceConfig.apply)
      .nested("app")

  /**
    * `application.conf` on the classpath, `${?ENV}` substitutions resolved. A required variable
    * that is not set (`${AUTH_ISSUER}`) is a [[zio.Config.Error]] like any other invalid value.
    */
  def load: IO[Config.Error, ServiceConfig] =
    ZIO
      .attempt(ConfigFactory.load().resolve())
      .mapError(e => invalid(e.getMessage))
      .flatMap(TypesafeConfigProvider.fromTypesafeConfig(_).load(descriptor))

  /**
    * For tests: the same descriptor over literal HOCON.
    */
  def fromHocon(hocon: String): IO[Config.Error, ServiceConfig] =
    TypesafeConfigProvider.fromHoconString(hocon).load(descriptor)

  // --- shared value readers -------------------------------------------------

  private[auth] def invalid(message: String): Config.Error =
    Config.Error.InvalidData(Chunk.empty, message)

  /**
    * A duration as HOCON writes it (`250 milliseconds`, `5 minutes`) or ISO-8601 (`PT5M`).
    */
  private[auth] def finiteDuration(name: String): Config[FiniteDuration] =
    Config.duration(name).mapOrFail { d =>
      if (d.isNegative) Left(invalid(s"$name must not be negative"))
      else Right(FiniteDuration(d.toNanos, NANOSECONDS))
    }

  private[auth] def nonBlank(name: String): Config[String] =
    Config
      .string(name)
      .mapOrFail(s => Either.cond(s.trim.nonEmpty, s, invalid(s"$name must not be blank")))

  private def level(name: String): Config[Level] =
    Config.string(name).withDefault("info").mapOrFail { raw =>
      Level.get(raw.trim).toRight(invalid(s"$name: '$raw' is not a log level"))
    }

}

/**
  * zio-http server binding and back-pressure knobs.
  *
  * @param maxInFlight
  *   requests handled concurrently before the excess is shed with `503`
  * @param requestTimeout
  *   upper bound on producing one response; past it the client gets `503`
  */
final case class HttpSettings(
    host: String,
    port: Int,
    idleTimeout: zio.Duration,
    shutdownTimeout: zio.Duration,
    maxInFlight: Int,
    requestTimeout: zio.Duration
)

object HttpSettings {

  val descriptor: Config[HttpSettings] =
    (ServiceConfig.nonBlank("host") ++
      Config
        .int("port")
        .mapOrFail(p =>
          Either.cond(p >= 1 && p <= 65535, p, ServiceConfig.invalid(s"port $p is out of range"))
        ) ++
      Config.duration("idle-timeout") ++
      Config.duration("shutdown-timeout") ++
      Config
        .int("max-in-flight")
        .mapOrFail(n =>
          Either.cond(n > 0, n, ServiceConfig.invalid("max-in-flight must be positive"))
        ) ++
      Config.duration("request-timeout")).map(HttpSettings.apply)

}

/**
  * The access-token rules; see [[auth.accesstoken.AccessTokenConfig]] for each field's meaning.
  * Issuer and JWKS URI are checked against the same refined types the http4s service uses.
  */
final case class AuthSettings(
    issuer: String :| IssuerUri,
    audience: String :| NonBlank,
    jwksUri: String :| HttpsUriNoFragment,
    cache: CacheSettings
) {

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

object AuthSettings {

  val descriptor: Config[AuthSettings] =
    (Config
      .string("issuer")
      .mapOrFail(_.refineEither[IssuerUri].left.map(e => ServiceConfig.invalid(s"issuer: $e"))) ++
      Config
        .string("audience")
        .mapOrFail(
          _.refineEither[NonBlank].left.map(e => ServiceConfig.invalid(s"audience: $e"))
        ) ++
      Config
        .string("jwks-uri")
        .mapOrFail(
          _.refineEither[HttpsUriNoFragment].left.map(e => ServiceConfig.invalid(s"jwks-uri: $e"))
        ) ++
      CacheSettings.descriptor.nested("cache")).map(AuthSettings.apply)

}

/**
  * Hot-path caches, per node.
  *
  * @param verifiedTokens
  *   verified tokens remembered (`0` disables)
  * @param verifiedTokenTtl
  *   cap on reusing one verification
  * @param revocationTtl
  *   how long a denylist answer is reused — the worst-case revocation delay it adds (`0` disables)
  */
final case class CacheSettings(
    verifiedTokens: Long,
    verifiedTokenTtl: FiniteDuration,
    revocationTtl: FiniteDuration
)

object CacheSettings {

  val descriptor: Config[CacheSettings] =
    (Config
      .long("verified-tokens")
      .mapOrFail(n =>
        Either.cond(n >= 0, n, ServiceConfig.invalid("verified-tokens must not be negative"))
      ) ++
      ServiceConfig.finiteDuration("verified-token-ttl") ++
      ServiceConfig.finiteDuration("revocation-ttl")).map(CacheSettings.apply)

}

/**
  * Standalone (one server) or cluster (seed list, topology discovered).
  */
enum RedisMode derives CanEqual {
  case Standalone, Cluster
}

final case class RedisNode(host: String, port: Int)

/**
  * The Redis revocation store. `password` is optional so local/dev can connect unauthenticated; TLS
  * and auth are the expected production posture. It is a `zio.Config.Secret`, so it never shows in
  * a logged config.
  *
  * @param commandTimeout
  *   upper bound on one denylist lookup; past it the request fails closed with `503`
  */
final case class RedisSettings(
    mode: RedisMode,
    nodes: List[RedisNode],
    username: String,
    password: Option[Config.Secret],
    database: Int,
    tls: Boolean,
    clientName: String,
    connectTimeout: FiniteDuration,
    pingInterval: FiniteDuration,
    pingTimeout: FiniteDuration,
    commandTimeout: FiniteDuration
) {

  /**
    * This module's Redis client configuration. The cats-effect and ZIO Sage clients each ship their
    * own `SageConfig`, so each service maps its own settings.
    */
  def toSageConfig: SageConfig = {
    val seeds    = nodes.map(node => Endpoint(node.host, node.port)).toVector
    val topology = mode match {
      // The descriptor guarantees a non-empty list, and exactly one standalone node.
      case RedisMode.Standalone => Topology.Standalone(seeds.head)
      case RedisMode.Cluster    => Topology.Cluster(seeds)
    }
    SageConfig(
      connectTimeout = connectTimeout,
      watchdog = WatchdogConfig(pingInterval = pingInterval, pingTimeout = pingTimeout),
      auth = password.map(pw => SageAuth(password = pw.stringValue, username = username)),
      tls = Option.when(tls)(TlsConfig(TrustSource.System)),
      topology = topology,
      database = database,
      clientName = Some(clientName)
    )
  }

}

object RedisSettings {

  private val mode: Config[RedisMode] =
    Config.string("mode").mapOrFail {
      case m if m.equalsIgnoreCase("standalone") => Right(RedisMode.Standalone)
      case m if m.equalsIgnoreCase("cluster")    => Right(RedisMode.Cluster)
      case other                                 => Left(ServiceConfig.invalid(s"mode: '$other' is not standalone or cluster"))
    }

  private val node: Config[RedisNode] =
    (ServiceConfig.nonBlank("host") ++ Config.int("port")).mapOrFail { case (host, port) =>
      Either.cond(
        port >= 1 && port <= 65535,
        RedisNode(host, port),
        ServiceConfig.invalid(s"port $port is out of range")
      )
    }

  // Present but blank is a deployment mistake (REDIS_PASSWORD=""), never "no password".
  private val password: Config[Option[Config.Secret]] =
    Config
      .secret("password")
      .optional
      .mapOrFail {
        case Some(pw) if pw.stringValue.trim.isEmpty =>
          Left(ServiceConfig.invalid("password must not be blank"))
        case other => Right(other)
      }

  val descriptor: Config[RedisSettings] =
    (mode ++
      Config.listOf("nodes", node) ++
      Config.string("username") ++
      password ++
      Config.int("database") ++
      Config.boolean("tls") ++
      ServiceConfig.nonBlank("client-name") ++
      ServiceConfig.finiteDuration("connect-timeout") ++
      ServiceConfig.finiteDuration("ping-interval") ++
      ServiceConfig.finiteDuration("ping-timeout") ++
      ServiceConfig.finiteDuration("command-timeout")).map(RedisSettings.apply).mapOrFail {
      settings =>
        // Cross-field rules, checked at load so a misconfiguration fails the boot
        // with a clear message instead of an opaque connection error later.
        if (settings.nodes.isEmpty) Left(ServiceConfig.invalid("nodes must not be empty"))
        else if (settings.mode == RedisMode.Standalone && settings.nodes.sizeIs != 1)
          Left(ServiceConfig.invalid("standalone mode expects exactly one node in nodes"))
        else if (settings.mode == RedisMode.Cluster && settings.database != 0)
          Left(ServiceConfig.invalid("cluster mode only supports database 0"))
        else if (settings.database < 0 || settings.database > 15)
          Left(ServiceConfig.invalid(s"database ${settings.database} is not in 0..15"))
        else Right(settings)
    }

}
