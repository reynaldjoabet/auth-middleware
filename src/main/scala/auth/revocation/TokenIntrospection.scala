package auth
package revocation

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

import scala.concurrent.duration.*

import cats.effect.Async
import cats.syntax.all.*
import com.github.benmanes.caffeine.cache.Caffeine
import io.circe.Json
import org.http4s.circe.*
import org.http4s.client.Client
import org.http4s.headers.Authorization
import org.http4s.{BasicCredentials, Method, Request, Uri, UrlForm}

/** Revocation checking via OAuth 2.0 Token Introspection (RFC 7662) — the
  * Duende pattern for revocation at a resource server: instead of every RS
  * maintaining a shared denylist (Redis), ask the authorization server, which
  * already owns revocation state. This removes the last piece of shared
  * infrastructure from the middleware.
  *
  * Trade-offs, mirroring `@RequireOAuth2(introspect = true)` on the Java side
  * and Duende's guidance:
  *   - a network hop per (uncached) check — gate it on the sensitive route
  *     groups rather than the whole API if latency matters; construct one
  *     [[JwtValidator]] with introspection for those routes and one without for
  *     the rest
  *   - failures are reported as [[Result.Unavailable]] and the validator fails
  *     closed (503, `Retry-After`) — a token we cannot prove active is not
  *     accepted
  *   - with `cacheTtl > 0` a positive result is reused, so revocation takes
  *     effect within `cacheTtl` at worst; set it to zero for hard real-time
  *     revocation at full network cost
  */
trait TokenIntrospection[F[_]] {

  /** Ask the authorization server whether `rawToken` is still active. */
  def check(rawToken: String): F[TokenIntrospection.Result]
}

object TokenIntrospection {

  enum Result derives CanEqual {
    case Active
    case Inactive

    /** Endpoint unreachable / non-success / unparsable — fail closed upstream.
      */
    case Unavailable
  }

  /** @param endpoint
    *   the AS's introspection endpoint; https only — credentials and tokens
    *   transit this connection
    * @param clientId
    *   this resource server's client id at the AS (RFC 7662 requires the caller
    *   to authenticate, otherwise introspection is a token oracle)
    * @param clientSecret
    *   secret for HTTP Basic authentication at the endpoint
    * @param cacheTtl
    *   how long a definitive answer (active / inactive) is reused for the same
    *   token. Bounds worst-case revocation latency; zero disables caching.
    * @param cacheMaxEntries
    *   cap on cached answers (keys are SHA-256 hashes, ~100 bytes/entry)
    */
  final case class IntrospectionConfig(
      endpoint: Uri,
      clientId: String,
      clientSecret: String,
      cacheTtl: FiniteDuration = 10.seconds,
      cacheMaxEntries: Long = 100_000L
  ) {
    require(
      endpoint.scheme.exists(_.value.equalsIgnoreCase("https")),
      "introspection endpoint must be https (client credentials and tokens transit it)"
    )
    require(clientId.nonEmpty, "clientId must not be empty")
    require(clientSecret.nonEmpty, "clientSecret must not be empty")
    require(cacheTtl >= Duration.Zero, "cacheTtl must not be negative")
  }

  /** Production implementation over an http4s [[Client]] (reuse the app's
    * pooled Ember client). Definitive answers are cached in-process, keyed by
    * SHA-256 of the token — raw tokens are never retained. `Unavailable` is
    * never cached, so a blip does not poison subsequent checks.
    */
  def http4s[F[_]: Async](
      config: IntrospectionConfig,
      client: Client[F]
  ): F[TokenIntrospection[F]] =
    Async[F].delay {
      val cache = Option.when(config.cacheTtl > Duration.Zero)(
        Caffeine
          .newBuilder()
          .expireAfterWrite(
            java.time.Duration.ofMillis(config.cacheTtl.toMillis)
          )
          .maximumSize(config.cacheMaxEntries)
          .build[String, Result]()
      )

      new TokenIntrospection[F] {

        def check(rawToken: String): F[Result] = {
          val key = tokenKey(rawToken)
          cache.flatMap(c => Option(c.getIfPresent(key))) match {
            case Some(cached) => cached.pure[F]
            case None         =>
              introspect(rawToken).flatTap {
                case definitive @ (Result.Active | Result.Inactive) =>
                  Async[F].delay(cache.foreach(_.put(key, definitive)))
                case Result.Unavailable => Async[F].unit
              }
          }
        }

        private def introspect(rawToken: String): F[Result] = {
          val request = Request[F](Method.POST, config.endpoint)
            .withEntity(UrlForm("token" -> rawToken))
            .putHeaders(
              Authorization(
                BasicCredentials(config.clientId, config.clientSecret)
              )
            )

          client
            .run(request)
            .use { response =>
              if (response.status.isSuccess)
                response
                  .as[Json]
                  .map(_.hcursor.get[Boolean]("active").getOrElse(false))
                  .map(active => if (active) Result.Active else Result.Inactive)
              else Result.Unavailable.pure[F].widen
            }
            .handleError(_ => Result.Unavailable)
        }
      }
    }

  /** Cache key: base64url(SHA-256(token)) — the raw token never sits in memory
    * beyond the request that carried it.
    */
  private def tokenKey(rawToken: String): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(
      MessageDigest
        .getInstance("SHA-256")
        .digest(rawToken.getBytes(StandardCharsets.US_ASCII))
    )
}
