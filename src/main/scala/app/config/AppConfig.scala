package app.config

import java.net.URI
import scala.concurrent.duration.FiniteDuration

import auth.{AuthConfig, HttpsUriNoFragment, IssuerUri, NonBlank}
import com.comcast.ip4s.{Host, Port}
import app.config.given
import io.github.iltotore.iron.constraint.all.*
import io.github.iltotore.iron.pureconfig.given
import pureconfig.ConfigReader
import io.github.iltotore.iron.*

final case class AppConfig(
    http: HttpServerConfig,
    db: DbConfig,
    auth: AuthSettings,
    redis: RedisSettings
) derives ConfigReader

/** Ember server binding and back-pressure knobs. */
final case class HttpServerConfig(
    host: Host,
    port: Port,
    idleTimeout: FiniteDuration,
    shutdownTimeout: FiniteDuration,
    maxConnections: Int
) derives ConfigReader

/** Database connection + HikariCP pool tuning. The password is a [[Secret]] so
  * the whole case class is safe to log.
  */
final case class DbConfig(
    host: String,
    port: Int :| Interval.Closed[1, 65535],
    name: String,
    user: String,
    password: String,
    maxPoolSize: Int,
    connectTimeout: FiniteDuration,
    maxLifetime: FiniteDuration,
    leakDetectionThreshold: FiniteDuration
) derives ConfigReader {
  def jdbcUrl: String = s"jdbc:postgresql://$host:$port/$name"
}

final case class AuthSettings(
    issuer: String :| IssuerUri,
    audience: String :| NonBlank,
    jwksUri: String :| HttpsUriNoFragment
) derives ConfigReader {
  def toAuthConfig: AuthConfig =
    AuthConfig(issuer, audience, URI.create(jwksUri))
}
