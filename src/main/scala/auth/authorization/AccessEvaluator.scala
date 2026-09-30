package auth
package authorization

import scala.concurrent.duration.*

import cats.effect.{Async, Sync}
import cats.effect.syntax.temporal.*
import cats.syntax.all.*

import com.github.benmanes.caffeine.cache.Caffeine
import io.circe.{Decoder, Encoder, Json, JsonObject}
import io.circe.syntax.*
import org.http4s.{Headers, Method, Request, Uri}
import org.http4s.circe.*
import org.http4s.client.Client
import org.http4s.headers.Authorization
import org.http4s.AuthScheme
import org.http4s.Credentials.Token

/**
  * Level 2 authorization: decisions that depend on current state or on the resource, which a token
  * cannot answer. "May this user read employee 123?", "does the user's role, as it is now, allow
  * this feature?". The API asks the IAM service's policy decision point (PDP) at request time.
  *
  * The request and response follow the OpenID AuthZEN Authorization API 1.0 access evaluation
  * (`POST /access/v1/evaluation`): a subject, an action, a resource and optional context in, a
  * boolean `decision` out. Any AuthZEN-conformant PDP can answer it.
  */
trait AccessEvaluator[F[_]] {

  /**
    * `true` to allow, `false` to deny. A PDP that cannot be reached, answers with an error or
    * answers late raises instead: the caller fails the request closed with `503`.
    */
  def evaluate(request: AuthZen.Request): F[Boolean]

}

/**
  * The AuthZEN evaluation request.
  */
object AuthZen {

  final case class Subject(`type`: String, id: String, properties: JsonObject = JsonObject.empty)

  final case class Action(name: String, properties: JsonObject = JsonObject.empty)

  final case class Resource(`type`: String, id: String, properties: JsonObject = JsonObject.empty)

  final case class Request(
      subject: Subject,
      action: Action,
      resource: Resource,
      context: JsonObject = JsonObject.empty
  )

  /**
    * The subject for a validated token: the user, or the calling client when no user is present (a
    * `client_credentials` token). `tenant` and `client_id` go along as properties so the PDP can
    * enforce tenant isolation and client restrictions too.
    *
    * The token's roles are not sent. Whether the user's roles, as they are now, allow the action is
    * exactly what the PDP is asked, from its own current data.
    */
  def subjectOf(ctx: AuthContext): Subject = {
    val properties = JsonObject.fromIterable(
      ctx.tenant.map(t => "tenant" -> Json.fromString(t.value)).toList ++
        ctx.clientId.map(c => "client_id" -> Json.fromString(c.value)).toList
    )
    if (AuthContext.userPresent(ctx)) Subject("user", ctx.subject.value, properties)
    else Subject("client", ctx.clientId.fold(ctx.subject.value)(_.value), properties)
  }

  private def withProperties(fields: (String, Json)*)(properties: JsonObject): Json =
    Json.fromFields(fields ++ Option.when(properties.nonEmpty)("properties" -> properties.asJson))

  given Encoder[Request] = Encoder.instance { r =>
    Json.fromFields(
      List(
        "subject" -> withProperties(
          "type" -> r.subject.`type`.asJson,
          "id"   -> r.subject.id.asJson
        )(r.subject.properties),
        "action"   -> withProperties("name" -> r.action.name.asJson)(r.action.properties),
        "resource" -> withProperties(
          "type" -> r.resource.`type`.asJson,
          "id"   -> r.resource.id.asJson
        )(r.resource.properties)
      ) ++ Option.when(r.context.nonEmpty)("context" -> r.context.asJson)
    )
  }

  private[authorization] final case class Decision(decision: Boolean)

  private[authorization] given Decoder[Decision] =
    Decoder.instance(_.downField("decision").as[Boolean].map(Decision.apply))

}

object AccessEvaluator {

  /**
    * @param endpoint
    *   the PDP's base URL; `/access/v1/evaluation` is appended. `https` only.
    * @param bearerToken
    *   sent as `Authorization: Bearer` to the PDP, when it requires one
    * @param requestTimeout
    *   past this the evaluation fails and the request is answered `503`
    * @param cacheTtl
    *   how long a decision is reused for an identical request. This is the worst-case delay before
    *   a policy change (a role removed in IAM) takes effect on a node; `0` asks the PDP every time.
    *   Errors are never cached.
    */
  final case class PdpConfig(
      endpoint: Uri,
      bearerToken: Option[String] = None,
      requestTimeout: FiniteDuration = 2.seconds,
      cacheTtl: FiniteDuration = 5.seconds,
      cacheMaxEntries: Long = 100_000L
  ) {

    require(
      endpoint.scheme.exists(_.value.equalsIgnoreCase("https")),
      "the PDP endpoint must be https: authorization decisions must not travel in the clear"
    )
    require(cacheTtl >= Duration.Zero, "cacheTtl must not be negative")

  }

  /**
    * An AuthZEN PDP over `client`, with decisions cached per `config.cacheTtl`.
    */
  def authZen[F[_]: Async](config: PdpConfig, client: Client[F]): F[AccessEvaluator[F]] = {
    val url  = config.endpoint.addPath("access/v1/evaluation")
    val auth = config.bearerToken.map(t => Authorization(Token(AuthScheme.Bearer, t)))

    val remote = new AccessEvaluator[F] {
      def evaluate(request: AuthZen.Request): F[Boolean] =
        client
          .expect[AuthZen.Decision](
            Request[F](Method.POST, url, headers = Headers(auth.toList))
              .withEntity(request.asJson)
          )(using jsonOf[F, AuthZen.Decision])
          .map(_.decision)
          .timeout(config.requestTimeout)
    }

    if (config.cacheTtl <= Duration.Zero) remote.pure[F]
    else cached(remote, config.cacheTtl, config.cacheMaxEntries)
  }

  /**
    * Reuses each decision for `ttl`. Errors are not cached, so a PDP blip does not outlive itself.
    */
  def cached[F[_]: Sync](
      underlying: AccessEvaluator[F],
      ttl: FiniteDuration,
      maxEntries: Long
  ): F[AccessEvaluator[F]] =
    Sync[F].delay {
      val decisions = Caffeine
        .newBuilder()
        .expireAfterWrite(java.time.Duration.ofNanos(ttl.toNanos))
        .maximumSize(maxEntries)
        .build[AuthZen.Request, java.lang.Boolean]()

      new AccessEvaluator[F] {
        def evaluate(request: AuthZen.Request): F[Boolean] =
          Sync[F].delay(Option(decisions.getIfPresent(request))).flatMap {
            case Some(decision) => (decision: Boolean).pure[F]
            case None           =>
              underlying
                .evaluate(request)
                .flatTap(decision => Sync[F].delay(decisions.put(request, decision)))
          }
      }
    }

}
