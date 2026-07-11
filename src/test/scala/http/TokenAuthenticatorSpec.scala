package http

import java.net.URI
import java.util.concurrent.{CompletableFuture, CompletionStage}
import java.util.function.Function as JFunction

import scala.jdk.CollectionConverters.*

import auth.service.{
  DPoPNonceService,
  DPoPProofVerifier,
  OAuthTokenValidator,
  TokenAuthenticator,
  TokenIntrospector
}
import auth.{OAuthAttrs, OAuthConfig, Principal, SecurityAttrs}
import com.nimbusds.jwt.JWTClaimsSet
import munit.FunSuite
import play.mvc.{Http, Result, Results}

/** Exercises the [[TokenAuthenticator]] pipeline shared by the composed
  * annotations and [[http.filters.AccessTokenAuthFilter]]: the OAuth 2.1
  * request-hygiene rejections, challenge shapes (RFC 6750 `WWW-Authenticate` +
  * `Cache-Control: no-store`), and the idempotence contract that lets the
  * app-wide filter compose with per-route annotations without spending a DPoP
  * proof's jti twice.
  *
  * Paths that need a validly signed token (cnf dispatch, proof verification,
  * nonce enforcement) are covered by the Scala stack's equivalent specs
  * ([[auth.AccessTokenAuthSpec]], [[auth.dpop.DpopVerifierSpec]]); this spec
  * pins everything reachable without a JWKS.
  */
class TokenAuthenticatorSpec extends FunSuite {

  private val config = OAuthConfig.of(
    "https://as.test.example",
    "https://api.test.example",
    URI.create("https://as.test.example/jwks")
  )

  private val authenticator = new TokenAuthenticator(
    config,
    new OAuthTokenValidator(config),
    new DPoPProofVerifier(config),
    new DPoPNonceService(config),
    new TokenIntrospector(config)
  )

  private val next: JFunction[Http.RequestHeader, CompletionStage[Result]] =
    _ => CompletableFuture.completedFuture(Results.ok("through"))

  private def run(
      req: Http.RequestHeader,
      requireDPoP: Boolean = false
  ): Result =
    authenticator
      .authenticate(req, requireDPoP, false, next)
      .toCompletableFuture
      .join()

  private def get(uri: String): Http.RequestBuilder =
    new Http.RequestBuilder().method("GET").uri(uri)

  private def header(r: Result, name: String): Option[String] =
    r.headers().asScala.get(name)

  private def challenge(r: Result): String =
    header(r, Http.HeaderNames.WWW_AUTHENTICATE).getOrElse("")

  // ── OAuth 2.1 request hygiene ───────────────────────────────────────────

  test("access token in the query string → 400 invalid_request") {
    val r = run(get("/x?access_token=abc").build())
    assertEquals(r.status(), 400)
    assert(challenge(r).contains("invalid_request"))
    assert(challenge(r).contains("query string"))
  }

  test(
    "query token is rejected even alongside a valid-looking Authorization header"
  ) {
    val r = run(
      get("/x?access_token=abc")
        .header(Http.HeaderNames.AUTHORIZATION, "Bearer sometoken")
        .build()
    )
    assertEquals(r.status(), 400)
    assert(challenge(r).contains("invalid_request"))
  }

  test("multiple Authorization headers → 400 invalid_request") {
    val headers = new Http.Headers(
      Map(
        Http.HeaderNames.AUTHORIZATION -> List("Bearer a", "Bearer b").asJava
      ).asJava
    )
    val r = run(get("/x").headers(headers).build())
    assertEquals(r.status(), 400)
    assert(challenge(r).contains("Multiple Authorization headers"))
  }

  test("no credentials → 401 with a Bearer challenge") {
    val r = run(get("/x").build())
    assertEquals(r.status(), 401)
    assert(challenge(r).startsWith("Bearer realm="))
  }

  test("no credentials with requireDPoP → DPoP challenge") {
    val r = run(get("/x").build(), requireDPoP = true)
    assertEquals(r.status(), 401)
    assert(challenge(r).startsWith("DPoP realm="))
  }

  test("unsupported scheme → 401 invalid_token") {
    val r = run(
      get("/x")
        .header(Http.HeaderNames.AUTHORIZATION, "Basic dXNlcjpwdw==")
        .build()
    )
    assertEquals(r.status(), 401)
    assert(challenge(r).contains("Unsupported token type"))
  }

  test("Bearer presentation on a requireDPoP pipeline → DPoP challenge") {
    val r = run(
      get("/x").header(Http.HeaderNames.AUTHORIZATION, "Bearer abc").build(),
      requireDPoP = true
    )
    assertEquals(r.status(), 401)
    assert(challenge(r).contains("requires DPoP-bound access tokens"))
  }

  test("oversized Authorization header → 400 before any parsing") {
    val r = run(
      get("/x")
        .header(
          Http.HeaderNames.AUTHORIZATION,
          "Bearer " + "a" * (config.proofMaxLength() + 1)
        )
        .build()
    )
    assertEquals(r.status(), 400)
    assert(challenge(r).contains("maximum length"))
  }

  test(
    "malformed token → 401 with a fixed description, no validator internals"
  ) {
    val r = run(
      get("/x")
        .header(Http.HeaderNames.AUTHORIZATION, "Bearer not-a-jwt")
        .build()
    )
    assertEquals(r.status(), 401)
    assert(challenge(r).contains("invalid_token"))
    assert(challenge(r).contains("Malformed token"))
  }

  test("every challenge carries Cache-Control: no-store (RFC 6749 §5.1)") {
    val challenges = List(
      run(get("/x?access_token=abc").build()),
      run(get("/x").build()),
      run(
        get("/x").header(Http.HeaderNames.AUTHORIZATION, "Bearer bad").build()
      )
    )
    challenges.foreach { r =>
      assertEquals(
        header(r, SecurityHeaders.CACHE_CONTROL),
        Some(SecurityHeaders.CACHE_CONTROL_NO_STORE)
      )
      assertEquals(
        header(r, SecurityHeaders.PRAGMA),
        Some(SecurityHeaders.PRAGMA_NO_CACHE)
      )
    }
  }

  // ── filter × annotation composition (idempotence) ──────────────────────

  private def preAuthenticated(dpopBound: Boolean): Http.Request = {
    val principal = new Principal(
      "user-123",
      "mobile-app",
      Set("accounts.read").asJava,
      null,
      Set.empty[String].asJava,
      null,
      new JWTClaimsSet.Builder().subject("user-123").build()
    )
    get("/x")
      .build()
      .addAttr(SecurityAttrs.PRINCIPAL, principal)
      .addAttr(OAuthAttrs.IS_DPOP_BOUND, dpopBound)
  }

  test(
    "an upstream-authenticated request passes through without re-validation"
  ) {
    // No Authorization header at all: a second full run would 401. Passing
    // proves the pipeline trusts the attrs instead of re-verifying (which for
    // DPoP would spend the proof's jti twice).
    val r = run(preAuthenticated(dpopBound = false))
    assertEquals(r.status(), 200)
  }

  test("requireDPoP delta is still enforced on a pre-authenticated request") {
    val r = run(preAuthenticated(dpopBound = false), requireDPoP = true)
    assertEquals(r.status(), 401)
    assert(challenge(r).contains("requires DPoP-bound access tokens"))

    val ok = run(preAuthenticated(dpopBound = true), requireDPoP = true)
    assertEquals(ok.status(), 200)
  }
}
