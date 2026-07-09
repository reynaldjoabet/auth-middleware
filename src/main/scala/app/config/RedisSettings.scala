package app.config

import scala.concurrent.duration.FiniteDuration
import _root_.pureconfig.ConfigReader
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*
import io.github.iltotore.iron.pureconfig.given

import sage.client.{
  AuthConfig as SageAuth,
  Endpoint,
  SageConfig,
  TlsConfig,
  Topology,
  TrustSource,
  WatchdogConfig
}

/** Standalone (one server) or cluster (seed list, topology discovered). */
enum RedisMode derives CanEqual {
  case Standalone, Cluster
}

object RedisMode {
  // `derives ConfigReader` on an enum produces a coproduct reader that expects
  // an OBJECT ({ standalone {} }); the config writes plain strings
  // (`mode = standalone`), which needs the enumeration form.
  given ConfigReader[RedisMode] =
    _root_.pureconfig.generic.semiauto.deriveEnumerationReader
}

/** A single Redis/Valkey address; refined so a blank host or out-of-range port
  * fails the boot.
  */
final case class RedisEndpoint(
    host: String :| Not[Blank],
    port: Int :| Interval.Closed[1, 65535]
) derives ConfigReader {
  def toEndpoint: Endpoint = Endpoint(host, port)
}

/** The environment-driven Redis configuration, mapped to a Sage [[SageConfig]].
  *
  * Only the deployment-specific knobs are exposed; Sage's own defaults cover
  * the rest (reconnect backoff, dedicated pool, client-side cache). `password`
  * is optional so local/dev can connect unauthenticated, but TLS + auth are the
  * expected production posture.
  */
final case class RedisSettings(
    mode: RedisMode,
    // Every entrypoint needs Redis (revocation denylist, and the shared DPoP jti
    // set behind a load balancer). Non-emptiness is a type-level invariant, so an
    // empty `redis.nodes` fails at config decode instead of letting Sage silently
    // fall back to a default localhost endpoint.
    nodes: List[RedisEndpoint] :| MinLength[1],
    username: String,
    password: Option[String],
    database: Int :| Interval.Closed[0, 15],
    tls: Boolean,
    clientName: String :| Not[Blank],
    connectTimeout: FiniteDuration,
    pingInterval: FiniteDuration,
    pingTimeout: FiniteDuration
) derives ConfigReader {

  // Cross-field invariants that a single-field refinement can't express. These
  // run during construction (and thus during ConfigReader decode), so a
  // misconfiguration fails the boot with a clear message rather than surfacing
  // as an opaque connection error later.
  require(
    mode != RedisMode.Standalone || nodes.sizeIs == 1,
    "redis: standalone mode expects exactly one node in redis.nodes"
  )
  require(
    mode != RedisMode.Cluster || database == 0,
    "redis: cluster mode only supports database 0"
  )

  def toSageConfig: SageConfig = {
    val seeds = nodes.map(_.toEndpoint).toVector
    val topology = mode match {
      // `seeds` is non-empty (MinLength[1]) and standalone is exactly one node.
      case RedisMode.Standalone => Topology.Standalone(seeds.head)
      case RedisMode.Cluster    => Topology.Cluster(seeds)
    }
    SageConfig(
      connectTimeout = connectTimeout,
      watchdog =
        WatchdogConfig(pingInterval = pingInterval, pingTimeout = pingTimeout),
      auth = password.map(pw => SageAuth(password = pw, username = username)),
      tls = Option.when(tls)(TlsConfig(TrustSource.System)),
      topology = topology,
      database = database,
      clientName = Some(clientName)
    )
  }
}
