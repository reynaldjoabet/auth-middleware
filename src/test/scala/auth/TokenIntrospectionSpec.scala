package auth

import scala.concurrent.duration.*

import cats.effect.{IO, Ref}
import io.circe.Json
import munit.CatsEffectSuite
import org.http4s.circe.*
import org.http4s.client.Client
import org.http4s.headers.Authorization
import org.http4s.implicits.*
import org.http4s.{BasicCredentials, HttpApp, Response, Status, UrlForm}

/** RFC 7662 introspection as the Redis-free revocation path (the Duende
  * pattern). Exercises the wire protocol (form POST, Basic auth), the
  * fail-closed mapping, the definitive-answer cache, and the validator wiring.
  */
class TokenIntrospectionSpec extends CatsEffectSuite {
  import TokenIntrospection.{IntrospectionConfig, Result}

  private val cfg = IntrospectionConfig(
    endpoint = uri"https://as.test.example/introspect",
    clientId = "rs-client",
    clientSecret = "s3cret"
  )

  /** Stub AS: rejects bad client credentials, then answers per `respond` over
    * the submitted `token` form field, counting upstream calls.
    */
  private def stubClient(
      calls: Ref[IO, Int],
      respond: String => IO[Response[IO]]
  ): Client[IO] =
    Client.fromHttpApp(HttpApp[IO] { req =>
      val authorized = req.headers.get[Authorization].exists {
        case Authorization(BasicCredentials(user, secret)) =>
          user == "rs-client" && secret == "s3cret"
        case _ => false
      }
      calls.update(_ + 1) *> {
        if (!authorized) IO.pure(Response[IO](Status.Unauthorized))
        else
          req
            .as[UrlForm]
            .flatMap(form => respond(form.getFirst("token").getOrElse("")))
      }
    })

  private def activeAnswer(active: Boolean): IO[Response[IO]] =
    IO.pure(
      Response[IO](Status.Ok)
        .withEntity(Json.obj("active" -> Json.fromBoolean(active)))
    )

  test("an active token is Active (auth + form field verified by the stub)") {
    for {
      calls <- Ref.of[IO, Int](0)
      introspection <- TokenIntrospection.http4s[IO](
        cfg,
        stubClient(
          calls,
          token =>
            if (token == "the-token") activeAnswer(true)
            else activeAnswer(false)
        )
      )
      result <- introspection.check("the-token")
    } yield assertEquals(result, Result.Active)
  }

  test("active=false is Inactive") {
    for {
      calls <- Ref.of[IO, Int](0)
      introspection <- TokenIntrospection
        .http4s[IO](cfg, stubClient(calls, _ => activeAnswer(false)))
      result <- introspection.check("t")
    } yield assertEquals(result, Result.Inactive)
  }

  test("a 5xx from the endpoint is Unavailable (fail closed upstream)") {
    for {
      calls <- Ref.of[IO, Int](0)
      introspection <- TokenIntrospection.http4s[IO](
        cfg,
        stubClient(
          calls,
          _ => IO.pure(Response[IO](Status.InternalServerError))
        )
      )
      result <- introspection.check("t")
    } yield assertEquals(result, Result.Unavailable)
  }

  test("an unparsable body is Unavailable, not accepted") {
    for {
      calls <- Ref.of[IO, Int](0)
      introspection <- TokenIntrospection.http4s[IO](
        cfg,
        stubClient(
          calls,
          _ => IO.pure(Response[IO](Status.Ok).withEntity("not json"))
        )
      )
      result <- introspection.check("t")
    } yield assertEquals(result, Result.Unavailable)
  }

  test("definitive answers are cached: one upstream call for two checks") {
    for {
      calls <- Ref.of[IO, Int](0)
      introspection <- TokenIntrospection
        .http4s[IO](cfg, stubClient(calls, _ => activeAnswer(true)))
      first <- introspection.check("t")
      second <- introspection.check("t")
      count <- calls.get
    } yield {
      assertEquals(first, Result.Active)
      assertEquals(second, Result.Active)
      assertEquals(count, 1)
    }
  }

  test("Unavailable is never cached: the next check goes back to the network") {
    for {
      calls <- Ref.of[IO, Int](0)
      healthy <- Ref.of[IO, Boolean](false)
      introspection <- TokenIntrospection.http4s[IO](
        cfg,
        stubClient(
          calls,
          _ =>
            healthy.get.flatMap {
              case true  => activeAnswer(true)
              case false => IO.pure(Response[IO](Status.BadGateway))
            }
        )
      )
      first <- introspection.check("t")
      _ <- healthy.set(true)
      second <- introspection.check("t")
      count <- calls.get
    } yield {
      assertEquals(first, Result.Unavailable)
      assertEquals(second, Result.Active)
      assertEquals(count, 2)
    }
  }

  test("cacheTtl = 0 disables caching") {
    for {
      calls <- Ref.of[IO, Int](0)
      introspection <- TokenIntrospection.http4s[IO](
        cfg.copy(cacheTtl = Duration.Zero),
        stubClient(calls, _ => activeAnswer(true))
      )
      _ <- introspection.check("t")
      _ <- introspection.check("t")
      count <- calls.get
    } yield assertEquals(count, 2)
  }

  // ── validator wiring ──────────────────────────────────────────────────────

  import TestTokens.*

  private def fixed(result: Result): TokenIntrospection[IO] =
    new TokenIntrospection[IO] {
      def check(rawToken: String): IO[Result] = IO.pure(result)
    }

  private def validatorWith(result: Result): JwtValidator[IO] =
    JwtValidator.fromKeySource[IO](
      config,
      keySource,
      AuthEvents.noop[IO],
      TokenDenylist.none[IO],
      Some(fixed(result))
    )

  test("validator accepts a token introspection reports active") {
    validatorWith(Result.Active)
      .validate(sign(claims()))
      .map(result => assert(result.isRight, result.toString))
  }

  test("validator rejects an inactive token as revoked") {
    validatorWith(Result.Inactive)
      .validate(sign(claims()))
      .map(result =>
        assertEquals[Option[AuthError], Option[AuthError]](
          result.left.toOption,
          Some(AuthError.InvalidToken.Revoked)
        )
      )
  }

  test("validator fails closed (503) when introspection is unavailable") {
    validatorWith(Result.Unavailable)
      .validate(sign(claims()))
      .map(result =>
        assertEquals[Option[AuthError], Option[AuthError]](
          result.left.toOption,
          Some(AuthError.ValidationUnavailable)
        )
      )
  }
}
