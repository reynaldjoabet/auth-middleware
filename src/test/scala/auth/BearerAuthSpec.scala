package auth
import auth.revocation.TokenDenylist

import cats.effect.IO
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*
import munit.CatsEffectSuite
import org.http4s.AuthScheme
import org.http4s.AuthedRoutes
import org.http4s.BasicCredentials
import org.http4s.Credentials
import org.http4s.Method
import org.http4s.Request
import org.http4s.Status
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Authorization
import org.http4s.implicits.*
import org.typelevel.ci.*

class BearerAuthSpec extends CatsEffectSuite {
  import TestTokens.*

  private object dsl extends Http4sDsl[IO]
  import dsl.*

  // -- fixtures ------------------------------------------------------------
  // All fields are declared before the first `test(...)` so that `this` is
  // fully initialized when each test closure is registered in the
  // constructor; otherwise -Ysafe-init warns about closures capturing a
  // partially-initialized `this`.

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

  private val sca = Acr("urn:openbanking:psd2:sca")

  // strength only
  private val acrApp = authMiddleware(
    BearerAuth.requireAcr[IO](sca)(paymentRoutes)
  ).orNotFound
  // strength + freshness, composed
  private def freshAcrApp(maxAge: MaxAuthAge) =
    authMiddleware(
      BearerAuth.requireAcr[IO](sca)(
        BearerAuth.requireFreshAuth[IO](maxAge)(paymentRoutes)
      )
    ).orNotFound
  // freshness only (any acr)
  private def freshApp(maxAge: MaxAuthAge) =
    authMiddleware(
      BearerAuth.requireFreshAuth[IO](maxAge)(paymentRoutes)
    ).orNotFound

  private val userApp = authMiddleware(
    BearerAuth.requireUser[IO]()(routes)
  ).orNotFound

  private val readScope = ScopeToken("accounts:read")

  // scopes (outer) → user (inner)
  private val scopeThenUser =
    authMiddleware(
      BearerAuth.requireScopes[IO](Set(readScope))(
        BearerAuth.requireUser[IO]()(routes)
      )
    ).orNotFound

  // user (outer) → scopes (inner): same checks, opposite precedence
  private val userThenScope =
    authMiddleware(
      BearerAuth.requireUser[IO]()(
        BearerAuth.requireScopes[IO](Set(readScope))(routes)
      )
    ).orNotFound

  // scopes → user → acr (full stack)
  private val fullStack =
    authMiddleware(
      BearerAuth.requireScopes[IO](Set(readScope))(
        BearerAuth.requireUser[IO]()(BearerAuth.requireAcr[IO](sca)(routes))
      )
    ).orNotFound

  // scopes (outer) → acr (inner): acr already implies a user, so this is the
  // "high-value, no explicit requireUser" pairing.
  private val scopeThenAcr =
    authMiddleware(
      BearerAuth.requireScopes[IO](Set(readScope))(
        BearerAuth.requireAcr[IO](sca)(routes)
      )
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

  private def payment(token: String) =
    Request[IO](Method.POST, uri"/payments")
      .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token)))

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

  private def withScope(
      base: com.nimbusds.jwt.JWTClaimsSet,
      scope: String
  ): com.nimbusds.jwt.JWTClaimsSet =
    new com.nimbusds.jwt.JWTClaimsSet.Builder(base)
      .claim("scope", scope)
      .build()

  private def assertError(resp: org.http4s.Response[IO], code: String): Unit = {
    val challenge =
      resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
    assert(challenge.contains(s"""error="$code""""), challenge)
  }

  // -- tests ---------------------------------------------------------------

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

  test("requireScopes with no required scopes admits any authenticated token") {
    val openApp =
      authMiddleware(BearerAuth.requireScopes[IO](Set.empty)(routes)).orNotFound
    openApp
      .run(get("/accounts", Some(sign(claims()))))
      .map(resp => assertEquals(resp.status, Status.Ok))
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
    "requireScopes: a custom realm appears in the insufficient_scope challenge"
  ) {
    val customApp = authMiddleware(
      BearerAuth
        .requireScopes[IO](Set(ScopeToken("payments:write")), realm = "bank")(
          paymentRoutes
        )
    ).orNotFound
    customApp.run(payment(sign(claims()))).map { resp =>
      assertEquals(resp.status, Status.Forbidden)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(challenge.contains("""realm="bank""""), challenge)
      assert(challenge.contains("""error="insufficient_scope""""), challenge)
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

  test(
    "503 with Retry-After (fail closed) when the key source is unavailable"
  ) {
    val downSource = new JWKSource[SecurityContext] {
      def get(
          selector: JWKSelector,
          ctx: SecurityContext
      ): java.util.List[JWK] =
        throw new KeySourceException("JWKS endpoint unreachable")
    }
    val downValidator = JwtValidator.fromKeySource[IO](
      config,
      downSource,
      AuthEvents.noop[IO],
      TokenDenylist.none[IO]
    )
    val downMw = BearerAuth.middleware(downValidator, AuthEvents.noop[IO])
    val downApp = downMw(routes).orNotFound
    downApp.run(get("/accounts", Some(sign(claims())))).map { resp =>
      assertEquals(resp.status, Status.ServiceUnavailable)
      assertEquals(
        resp.headers.get(ci"Retry-After").map(_.head.value),
        Some("5")
      )
      assertEquals(
        resp.headers.get(ci"Cache-Control").map(_.head.value),
        Some("no-store")
      )
    }
  }

  // ------------------------------------------------------- step-up (RFC 9470)

  test(
    "requireAcr: 401 insufficient_user_authentication when the token's acr is too weak"
  ) {
    import scala.concurrent.duration.*
    acrApp.run(payment(sign(acrClaims(None, 1.minute)))).map { resp =>
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

  test("requireAcr: 200 when the token satisfies the required acr") {
    import scala.concurrent.duration.*
    acrApp
      .run(payment(sign(acrClaims(Some("urn:openbanking:psd2:sca"), 1.minute))))
      .map(resp => assertEquals(resp.status, Status.Ok))
  }

  test(
    "requireAcr: 401 when the token's acr is present but not an acceptable value"
  ) {
    import scala.concurrent.duration.*
    acrApp
      .run(
        payment(sign(acrClaims(Some("urn:openbanking:psd2:loa1"), 1.minute)))
      )
      .map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        val challenge =
          resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
        assert(
          challenge.contains("""error="insufficient_user_authentication""""),
          challenge
        )
      }
  }

  test(
    "requireAcr: a token whose acr matches a non-first acceptable value -> 200"
  ) {
    import scala.concurrent.duration.*
    val app = authMiddleware(
      BearerAuth.requireAcr[IO](Acr("loa2"), Acr("loa3"))(paymentRoutes)
    ).orNotFound
    app
      .run(payment(sign(acrClaims(Some("loa3"), 1.minute))))
      .map(resp => assertEquals(resp.status, Status.Ok))
  }

  test(
    "requireAcr: the acr_values challenge preserves declared preference order"
  ) {
    import scala.concurrent.duration.*
    val app = authMiddleware(
      BearerAuth.requireAcr[IO](Acr("loa3"), Acr("loa2"), Acr("loa1"))(
        paymentRoutes
      )
    ).orNotFound
    app.run(payment(sign(acrClaims(Some("loa0"), 1.minute)))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      // declared order (loa3 loa2 loa1), not alphabetical (loa1 loa2 loa3)
      assert(challenge.contains("""acr_values="loa3 loa2 loa1""""), challenge)
    }
  }

  test("requireAcr: duplicate acr values are de-duplicated in the challenge") {
    import scala.concurrent.duration.*
    val app = authMiddleware(
      BearerAuth.requireAcr[IO](sca, sca)(paymentRoutes)
    ).orNotFound
    app.run(payment(sign(acrClaims(None, 1.minute)))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      // single value: closing quote follows immediately, so it is not repeated
      assert(
        challenge.contains("""acr_values="urn:openbanking:psd2:sca""""),
        challenge
      )
    }
  }

  test("requireAcr: a custom realm appears in the challenge") {
    import scala.concurrent.duration.*
    val app = authMiddleware(
      BearerAuth.requireAcr[IO](sca)(paymentRoutes, realm = "bank")
    ).orNotFound
    app.run(payment(sign(acrClaims(None, 1.minute)))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(challenge.contains("""realm="bank""""), challenge)
      assert(
        challenge.contains("""error="insufficient_user_authentication""""),
        challenge
      )
    }
  }

  test(
    "requireAcr + requireFreshAuth: 401 with max_age when acr ok but authentication too old"
  ) {
    import scala.concurrent.duration.*
    freshAcrApp(MaxAuthAge.applyUnsafe(300))
      .run(
        payment(sign(acrClaims(Some("urn:openbanking:psd2:sca"), 30.minutes)))
      )
      .map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        val challenge =
          resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
        assert(challenge.contains("max_age=300"), challenge)
      }
  }

  test(
    "requireAcr + requireFreshAuth: 200 when acr ok and authentication recent"
  ) {
    import scala.concurrent.duration.*
    freshAcrApp(MaxAuthAge.applyUnsafe(300))
      .run(payment(sign(acrClaims(Some("urn:openbanking:psd2:sca"), 1.minute))))
      .map(resp => assertEquals(resp.status, Status.Ok))
  }

  test(
    "requireFreshAuth: admits a recently-authenticated user regardless of acr"
  ) {
    import scala.concurrent.duration.*
    freshApp(MaxAuthAge.applyUnsafe(300))
      .run(payment(sign(acrClaims(None, 1.minute))))
      .map(resp => assertEquals(resp.status, Status.Ok))
  }

  test("requireFreshAuth: 401 with max_age when the token has no auth_time") {
    import scala.concurrent.duration.*
    freshApp(MaxAuthAge.applyUnsafe(300)).run(payment(sign(claims()))).map {
      resp =>
        assertEquals(resp.status, Status.Unauthorized)
        val challenge =
          resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
        assert(challenge.contains("max_age=300"), challenge)
    }
  }

  test("requireFreshAuth: a custom realm appears in the challenge") {
    val app = authMiddleware(
      BearerAuth.requireFreshAuth[IO](
        MaxAuthAge.applyUnsafe(300),
        "bank"
      )(paymentRoutes)
    ).orNotFound
    app.run(payment(sign(claims()))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(challenge.contains("""realm="bank""""), challenge)
      assert(challenge.contains("max_age=300"), challenge)
    }
  }

  test(
    "requireFreshAuth: max_age=0 rejects a prior authentication and emits max_age=0"
  ) {
    import scala.concurrent.duration.*
    val app = authMiddleware(
      BearerAuth.requireFreshAuth[IO](MaxAuthAge.applyUnsafe(0))(paymentRoutes)
    ).orNotFound
    app
      .run(payment(sign(acrClaims(Some("urn:openbanking:psd2:sca"), 1.minute))))
      .map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        val challenge =
          resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
        assert(challenge.contains("max_age=0"), challenge)
      }
  }

  // ------------------------------------------------------- requireMfa (preset)

  test("requireMfa: 401 acr_values=acr3 when the token carries no acr") {
    import scala.concurrent.duration.*
    val app =
      authMiddleware(BearerAuth.requireMfa[IO]()(paymentRoutes)).orNotFound
    app.run(payment(sign(acrClaims(None, 1.minute)))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(
        challenge.contains("""error="insufficient_user_authentication""""),
        challenge
      )
      assert(challenge.contains("""acr_values="acr3""""), challenge)
    }
  }

  test(
    "requireMfa: 401 max_age=300 when acr3 is present but authentication is stale"
  ) {
    import scala.concurrent.duration.*
    val app =
      authMiddleware(BearerAuth.requireMfa[IO]()(paymentRoutes)).orNotFound
    app.run(payment(sign(acrClaims(Some("acr3"), 30.minutes)))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(challenge.contains("max_age=300"), challenge)
    }
  }

  test(
    "requireMfa: 200 when the token carries acr3 and recent authentication"
  ) {
    import scala.concurrent.duration.*
    val app =
      authMiddleware(BearerAuth.requireMfa[IO]()(paymentRoutes)).orNotFound
    app
      .run(payment(sign(acrClaims(Some("acr3"), 1.minute))))
      .map(resp => assertEquals(resp.status, Status.Ok))
  }

  test("requireMfa: honors a custom mfaAcr and maxAge") {
    import scala.concurrent.duration.*
    val app = authMiddleware(
      BearerAuth.requireMfa[IO](Acr("loa3"), MaxAuthAge.applyUnsafe(60))(
        paymentRoutes
      )
    ).orNotFound
    for {
      // wrong acr -> challenge advertises the custom acr
      rejected <- app.run(payment(sign(acrClaims(Some("acr3"), 1.minute))))
      // right acr, fresh within the custom 60s window -> admitted
      admitted <- app.run(payment(sign(acrClaims(Some("loa3"), 30.seconds))))
    } yield {
      assertEquals(rejected.status, Status.Unauthorized)
      val challenge =
        rejected.headers
          .get(ci"WWW-Authenticate")
          .map(_.head.value)
          .getOrElse("")
      assert(challenge.contains("""acr_values="loa3""""), challenge)
      assertEquals(admitted.status, Status.Ok)
    }
  }

  // ------------------------------------------------------- requireUser (user vs M2M)

  test("requireUser admits a user-delegated token (sub != client_id)") {
    userApp
      .run(get("/accounts", Some(sign(claims()))))
      .map(resp => assertEquals(resp.status, Status.Ok))
  }

  test("requireUser rejects an M2M token (sub == client_id)") {
    userApp.run(get("/accounts", Some(sign(claims(sub = "mobile-app"))))).map {
      resp =>
        assertEquals(resp.status, Status.Unauthorized)
        val challenge =
          resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
        assert(
          challenge.contains("""error="insufficient_user_authentication""""),
          challenge
        )
    }
  }

  test("requireUser: a custom isUserPresent predicate overrides the default") {
    import scala.concurrent.duration.*
    // Treat "user present" as "the token carries an acr", regardless of sub.
    val app = authMiddleware(
      BearerAuth.requireUser[IO](isUserPresent = _.acr.isDefined)(routes)
    ).orNotFound
    for {
      // default userPresent would admit (sub != client_id), but no acr present
      rejected <- app.run(get("/accounts", Some(sign(claims()))))
      // carries an acr -> admitted by the override
      admitted <- app.run(
        get("/accounts", Some(sign(acrClaims(Some("loa1"), 1.minute))))
      )
    } yield {
      assertEquals(rejected.status, Status.Unauthorized)
      assertError(rejected, "insufficient_user_authentication")
      assertEquals(admitted.status, Status.Ok)
    }
  }

  // ------------------------------------------------------- composing the gates

  test("scopes+user: a user token carrying the scope passes both gates") {
    scopeThenUser
      .run(get("/accounts", Some(sign(claims()))))
      .map(resp => assertEquals(resp.status, Status.Ok))
  }

  test(
    "scopes+user: a user token missing the scope -> 403 insufficient_scope"
  ) {
    scopeThenUser
      .run(get("/accounts", Some(sign(claims(scope = Some("payments:read"))))))
      .map { resp =>
        assertEquals(resp.status, Status.Forbidden)
        assertError(resp, "insufficient_scope")
      }
  }

  test(
    "scopes+user: an M2M token with the scope -> 401 (fails the user gate)"
  ) {
    scopeThenUser
      .run(get("/accounts", Some(sign(claims(sub = "mobile-app")))))
      .map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        assertError(resp, "insufficient_user_authentication")
      }
  }

  test(
    "gate order decides the reported error: scopes-outer -> 403 for an M2M token also missing the scope"
  ) {
    val token = sign(
      claims(sub = "mobile-app", scope = Some("payments:read"))
    ) // M2M AND missing scope
    scopeThenUser.run(get("/accounts", Some(token))).map { resp =>
      assertEquals(resp.status, Status.Forbidden)
      assertError(resp, "insufficient_scope")
    }
  }

  test(
    "gate order decides the reported error: user-outer -> 401 for the same token"
  ) {
    val token = sign(claims(sub = "mobile-app", scope = Some("payments:read")))
    userThenScope.run(get("/accounts", Some(token))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      assertError(resp, "insufficient_user_authentication")
    }
  }

  test("scopes+user+acr: all three satisfied -> 200") {
    import scala.concurrent.duration.*
    val token = sign(acrClaims(Some("urn:openbanking:psd2:sca"), 1.minute))
    fullStack
      .run(get("/accounts", Some(token)))
      .map(resp => assertEquals(resp.status, Status.Ok))
  }

  test(
    "scopes+user+acr: scope and user ok but no acr -> 401 insufficient_user_authentication"
  ) {
    fullStack.run(get("/accounts", Some(sign(claims())))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      assertError(resp, "insufficient_user_authentication")
    }
  }

  test("scopes+user+acr: missing the scope -> 403 from the outer gate") {
    fullStack
      .run(get("/accounts", Some(sign(claims(scope = Some("payments:read"))))))
      .map { resp =>
        assertEquals(resp.status, Status.Forbidden)
        assertError(resp, "insufficient_scope")
      }
  }

  test("scopes+user+acr: a present but non-matching acr -> 401") {
    import scala.concurrent.duration.*
    val token = sign(
      acrClaims(Some("urn:openbanking:psd2:loa1"), 1.minute)
    ) // user + scope, wrong acr
    fullStack.run(get("/accounts", Some(token))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      assertError(resp, "insufficient_user_authentication")
    }
  }

  test("scopes+acr: scope present and a matching acr -> 200") {
    import scala.concurrent.duration.*
    val token = sign(acrClaims(Some("urn:openbanking:psd2:sca"), 1.minute))
    scopeThenAcr
      .run(get("/accounts", Some(token)))
      .map(resp => assertEquals(resp.status, Status.Ok))
  }

  test(
    "scopes+acr: scope ok but a non-matching acr -> 401 insufficient_user_authentication"
  ) {
    import scala.concurrent.duration.*
    val token = sign(acrClaims(Some("urn:openbanking:psd2:loa1"), 1.minute))
    scopeThenAcr.run(get("/accounts", Some(token))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      assertError(resp, "insufficient_user_authentication")
    }
  }

  test(
    "scopes+acr: missing the scope -> 403 even when the acr matches (outer gate)"
  ) {
    import scala.concurrent.duration.*
    val token = sign(
      withScope(
        acrClaims(Some("urn:openbanking:psd2:sca"), 1.minute),
        "payments:read"
      )
    )
    scopeThenAcr.run(get("/accounts", Some(token))).map { resp =>
      assertEquals(resp.status, Status.Forbidden)
      assertError(resp, "insufficient_scope")
    }
  }
}
