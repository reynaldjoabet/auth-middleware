package auth

import cats.effect.IO
import munit.CatsEffectSuite
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Authorization
import org.http4s.implicits.*
import org.http4s.{
  AuthScheme,
  AuthedRoutes,
  BasicCredentials,
  Credentials,
  Method,
  Request,
  Status
}
import org.typelevel.ci.*

import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*

class BearerAuthSpec extends CatsEffectSuite {
  import TestTokens.*

  private object dsl extends Http4sDsl[IO]
  import dsl.*

  private val validator =
    JwtValidator.fromKeySource[IO](
      config,
      keySource,
      AuthEvents.noop[IO],
      TokenDenylist.none[IO]
    )

  private val routes: AuthedRoutes[AuthContext, IO] = AuthedRoutes.of {
    case GET -> Root / "accounts" as ctx => Ok(ctx.subject.value: String)
  }

  private val paymentRoutes: AuthedRoutes[AuthContext, IO] = AuthedRoutes.of {
    case POST -> Root / "payments" as ctx =>
      Ok(s"payment by ${ctx.subject.value: String}")
  }

  private val authMiddleware =
    BearerAuth.middleware(validator, AuthEvents.noop[IO])

  private val app = authMiddleware(routes).orNotFound

  private val paymentsApp =
    authMiddleware(
      BearerAuth.requireScopes[IO](Set(ScopeToken("payments:write")))(
        paymentRoutes
      )
    ).orNotFound

  private val multiScopeApp =
    authMiddleware(
      BearerAuth.requireScopes[IO](
        Set(ScopeToken("payments:write"), ScopeToken("accounts:read"))
      )(paymentRoutes)
    ).orNotFound

  private def get(path: String, token: Option[String]): Request[IO] = {
    val req = Request[IO](
      Method.GET,
      uri"/".withPath(org.http4s.Uri.Path.unsafeFromString(path))
    )
    token.fold(req)(t =>
      req.putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, t)))
    )
  }

  test("401 with a bare Bearer challenge when no credentials are sent") {
    app.run(get("/accounts", None)).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge = resp.headers.get(ci"WWW-Authenticate").map(_.head.value)
      assertEquals(challenge, Some("""Bearer realm="api""""))
    }
  }

  test("401 invalid_token for a non-Bearer scheme") {
    val req = get("/accounts", None).putHeaders(
      Authorization(BasicCredentials("u", "p"))
    )
    app.run(req).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(challenge.contains("""error="invalid_token""""), challenge)
    }
  }

  test("401 invalid_token for a forged token, without echoing detail") {
    app.run(get("/accounts", Some(sign(claims(), key = rogueKey)))).flatMap {
      resp =>
        assertEquals(resp.status, Status.Unauthorized)
        resp.as[String].map { body =>
          assertEquals(
            body,
            """{"error":"invalid_token","error_description":"token signature, type or claims validation failed"}"""
          )
        }
    }
  }

  test("200 with the authenticated subject for a valid token") {
    app.run(get("/accounts", Some(sign(claims())))).flatMap { resp =>
      assertEquals(resp.status, Status.Ok)
      resp.as[String].assertEquals("user-123")
    }
  }

  test("403 insufficient_scope when the token lacks a required scope") {
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(
        Authorization(Credentials.Token(AuthScheme.Bearer, sign(claims())))
      )
    paymentsApp.run(req).map { resp =>
      assertEquals(resp.status, Status.Forbidden)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(challenge.contains("""error="insufficient_scope""""), challenge)
      assert(challenge.contains("""scope="payments:write""""), challenge)
    }
  }

  test("200 when the token carries the required scope") {
    val token = sign(claims(scope = Some("payments:write accounts:read")))
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    paymentsApp.run(req).map(resp => assertEquals(resp.status, Status.Ok))
  }

  test("200 when the token carries all of several required scopes") {
    val token = sign(claims(scope = Some("accounts:read payments:write")))
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    multiScopeApp.run(req).map(resp => assertEquals(resp.status, Status.Ok))
  }

  test("403 when the token is missing one of several required scopes") {
    val token = sign(claims(scope = Some("payments:write")))
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    multiScopeApp.run(req).map { resp =>
      assertEquals(resp.status, Status.Forbidden)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(
        challenge.contains("""scope="accounts:read payments:write""""),
        challenge
      )
    }
  }

  test(
    "400 invalid_request when the access token is sent in the query string"
  ) {
    val req = Request[IO](
      Method.GET,
      uri"/accounts".withQueryParam("access_token", sign(claims()))
    )
    app.run(req).map { resp =>
      assertEquals(resp.status, Status.BadRequest)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(challenge.contains("""error="invalid_request""""), challenge)
    }
  }

  test(
    "400 invalid_request when multiple Authorization headers are presented"
  ) {
    val req = get("/accounts", None).withHeaders(
      org.http4s.Headers(
        org.http4s.Header.Raw(ci"Authorization", s"Bearer ${sign(claims())}"),
        org.http4s.Header.Raw(ci"Authorization", s"Bearer ${sign(claims())}")
      )
    )
    app.run(req).map(resp => assertEquals(resp.status, Status.BadRequest))
  }

  test("authentication error responses carry Cache-Control: no-store") {
    app.run(get("/accounts", None)).map { resp =>
      assertEquals(
        resp.headers.get(ci"Cache-Control").map(_.head.value),
        Some("no-store")
      )
    }
  }

  // ------------------------------------------------------- step-up (RFC 9470)

  private def stepUpApp(
      maxAge: Option[scala.concurrent.duration.FiniteDuration] = None
  ) =
    authMiddleware(
      BearerAuth.requireAcr[IO](Set(Acr("urn:openbanking:psd2:sca")), maxAge)(
        paymentRoutes
      )
    ).orNotFound

  private def acrClaims(
      acr: Option[String],
      authTimeAgo: scala.concurrent.duration.FiniteDuration
  ) = {
    val b = new com.nimbusds.jwt.JWTClaimsSet.Builder(claims())
      .claim(
        "auth_time",
        new java.util.Date(System.currentTimeMillis() - authTimeAgo.toMillis)
      )
    acr.foreach(b.claim("acr", _))
    b.build()
  }

  test(
    "401 insufficient_user_authentication when the token's acr is too weak"
  ) {
    import scala.concurrent.duration.*
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(
        Authorization(
          Credentials.Token(AuthScheme.Bearer, sign(acrClaims(None, 1.minute)))
        )
      )
    stepUpApp().run(req).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(
        challenge.contains("""error="insufficient_user_authentication""""),
        challenge
      )
      assert(
        challenge.contains("""acr_values="urn:openbanking:psd2:sca""""),
        challenge
      )
    }
  }

  test("200 when the token satisfies the required acr") {
    import scala.concurrent.duration.*
    val token = sign(acrClaims(Some("urn:openbanking:psd2:sca"), 1.minute))
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    stepUpApp().run(req).map(resp => assertEquals(resp.status, Status.Ok))
  }

  test("401 when the token's acr is present but not an acceptable value") {
    import scala.concurrent.duration.*
    val token = sign(acrClaims(Some("urn:openbanking:psd2:loa1"), 1.minute))
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    stepUpApp().run(req).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(
        challenge.contains("""error="insufficient_user_authentication""""),
        challenge
      )
    }
  }

  test("requireAcr with no acceptable values admits any authenticated user") {
    val emptyAcrApp = authMiddleware(
      BearerAuth.requireAcr[IO](Set.empty[Acr])(paymentRoutes)
    ).orNotFound
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(
        Authorization(Credentials.Token(AuthScheme.Bearer, sign(claims())))
      )
    emptyAcrApp.run(req).map(resp => assertEquals(resp.status, Status.Ok))
  }

  test("401 with max_age when the authentication is fresh in acr but too old") {
    import scala.concurrent.duration.*
    val token = sign(acrClaims(Some("urn:openbanking:psd2:sca"), 30.minutes))
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    stepUpApp(maxAge = Some(5.minutes)).run(req).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(challenge.contains("max_age=300"), challenge)
    }
  }

  test("200 when the authentication is recent enough for max_age") {
    import scala.concurrent.duration.*
    val token = sign(acrClaims(Some("urn:openbanking:psd2:sca"), 1.minute))
    val req = Request[IO](Method.POST, uri"/payments")
      .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    stepUpApp(maxAge = Some(5.minutes))
      .run(req)
      .map(resp => assertEquals(resp.status, Status.Ok))
  }
}
