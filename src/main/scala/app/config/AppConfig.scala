package app.config

import java.net.URI
import java.util.Base64

import javax.crypto.SecretKey

import scala.concurrent.duration.FiniteDuration

import auth.dpop.DpopNonceValidator
import auth.revocation.TokenIntrospection
import auth.accesstoken.AccessTokenConfig
import auth.{HttpsUriNoFragment, IssuerUri, NonBlank}
import com.comcast.ip4s.{Host, Port}
import app.config.given
import io.github.iltotore.iron.constraint.all.*
import io.github.iltotore.iron.pureconfig.given
import org.http4s.Uri
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
    jwksUri: String :| HttpsUriNoFragment,
    dpop: DpopSettings,
    introspection: IntrospectionSettings
) derives ConfigReader {
  def toAccessTokenConfig: AccessTokenConfig =
    AccessTokenConfig(issuer, audience, URI.create(jwksUri))
}

/** RFC 9449 DPoP sender-constrained tokens. When enabled, the middleware
  * accepts the `DPoP` scheme and verifies proofs; `nonce` additionally requires
  * server-provided nonces on every proof (the FAPI 2.0 replay fix).
  */
final case class DpopSettings(
    enabled: Boolean,
    nonce: DpopNonceSettings
) derives ConfigReader

/** Stateless (Duende-pattern) nonce keys: base64-encoded AES key material
  * (16/24/32 bytes) shared by every node via the secret manager. `key` absent →
  * an ephemeral per-process key is generated at boot (single-node/dev only;
  * logged loudly). `previousKeys` keeps in-flight nonces valid during key
  * rotation.
  */
final case class DpopNonceSettings(
    enabled: Boolean,
    key: Option[String],
    previousKeys: List[String],
    lifetime: FiniteDuration
) derives ConfigReader {

  def decodedKey: Option[SecretKey] = key.map(decode)

  def decodedPreviousKeys: List[SecretKey] = previousKeys.map(decode)

  private def decode(base64: String): SecretKey =
    DpopNonceValidator.keyFromBytes(Base64.getDecoder.decode(base64))
}

/** RFC 7662 revocation checking against the AS — the Redis-free alternative to
  * a distributed denylist. Endpoint and client credentials are required when
  * enabled; the boot fails otherwise.
  */
final case class IntrospectionSettings(
    enabled: Boolean,
    endpoint: Option[String :| HttpsUriNoFragment],
    clientId: Option[String :| NonBlank],
    clientSecret: Option[String :| NonBlank],
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
        clientSecret = required(clientSecret, "client-secret"),
        cacheTtl = cacheTtl,
        requestTimeout = requestTimeout
      )
    }
}
