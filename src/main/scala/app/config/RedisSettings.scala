package app.config

import scala.concurrent.duration.FiniteDuration
import pureconfig.ConfigReader
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
enum RedisMode derives ConfigReader, CanEqual {
  case Standalone, Cluster
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
    nodes: List[RedisEndpoint],
    username: String,
    password: Option[String],
    database: Int :| Interval.Closed[0, 15],
    tls: Boolean,
    clientName: String :| Not[Blank],
    connectTimeout: FiniteDuration,
    pingInterval: FiniteDuration,
    pingTimeout: FiniteDuration
) derives ConfigReader {

  def toSageConfig: SageConfig = {
    val seeds = nodes.map(_.toEndpoint).toVector
    val topology = mode match {
      case RedisMode.Standalone =>
        Topology.Standalone(seeds.headOption.getOrElse(Endpoint()))
      case RedisMode.Cluster => Topology.Cluster(seeds)
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
