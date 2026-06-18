package auth

import scala.concurrent.duration.*

import cats.effect.IO
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.{JWK, JWKSelector}
import com.nimbusds.jose.{JOSEObjectType, KeySourceException}
import com.nimbusds.jwt.JWTClaimsSet
import io.github.iltotore.iron.*
import munit.CatsEffectSuite

class JwtValidatorSpec extends CatsEffectSuite {
  import TestTokens.*

  private def validator(
      cfg: AuthConfig = config,
      denylist: TokenDenylist[IO] = TokenDenylist.none[IO]
  ): JwtValidator[IO] =
    JwtValidator
      .fromKeySource[IO](cfg, keySource, AuthEvents.noop[IO], denylist)

  // The default token claims minus the named claim(s), to exercise the RFC 9068
  // §2.2 required-claims check. Round-trips through the JSON object so the key is
  // genuinely absent (Nimbus rejects a missing required claim before our own
  // checks run, surfacing as a generic invalid_token).
  private def claimsWithout(drop: String*): JWTClaimsSet = {
    val json = claims().toJSONObject
    drop.foreach(c => json.remove(c))
    JWTClaimsSet.parse(json)
  }

  // Test events sink capturing the internal detail of each failure, so the
  // omission tests can assert the specific Nimbus message (which the validator
  // routes to authFailed's internalDetail, not into the client-facing AuthError).
  private final class CapturingEvents extends AuthEvents[IO] {
    private val buf = scala.collection.mutable.ListBuffer.empty[String]
    def authSucceeded(ctx: AuthContext): IO[Unit] = IO.unit
    def authFailed(error: AuthError, internalDetail: String): IO[Unit] =
      IO(buf += internalDetail)
    def details: List[String] = buf.toList
  }

  // Each default required claim missing, then 2, 3, 4, and all of them. Every
  // case must be rejected as invalid_token, and the internal detail must name
  // exactly the missing claims — Nimbus reports them sorted (TreeSet). Default
  // requiredClaims = sub, exp, iat, client_id, jti; iss/aud stay present so the
  // reported missing set is exactly what we drop.
  (List("sub", "exp", "iat", "client_id", "jti").map(List(_)) ::: List(
    List("exp", "iat"),
    List("exp", "iat", "jti"),
    List("sub", "exp", "iat", "client_id"),
    List("sub", "exp", "iat", "client_id", "jti")
  )).foreach { drop =>
    test(s"rejects a token missing required claim(s): ${drop.mkString(", ")}") {
      val events = new CapturingEvents
      val v = JwtValidator
        .fromKeySource[IO](config, keySource, events, TokenDenylist.none[IO])
      v.validate(sign(claimsWithout(drop*))).map { result =>
        assertEquals(result, Left(AuthError.InvalidToken.Rejected))
        assertEquals(
          events.details,
          List(
            s"JWT missing required claims: ${drop.sorted.mkString("[", ", ", "]")}"
          )
        )
      }
    }
  }

  test("accepts a valid token and exposes subject, client, scopes and jti") {
    validator().validate(sign(claims())).map { result =>
      val ctx = result.fold(e => fail(s"expected success, got $e"), identity)
      assertEquals(ctx.subject.value: String, "user-123")
      assertEquals(ctx.clientId.map(c => c.value: String), Some("mobile-app"))
      assertEquals(
        ctx.scopes.map(s => s.value: String),
        Set("accounts:read", "payments:read")
      )
      assertEquals(ctx.tokenId.map(j => j.value: String), Some("jti-abc"))
    }
  }

  test("hasScope reflects the token's granted scopes") {
    validator().validate(sign(claims())).map { result =>
      val ctx = result.fold(e => fail(s"expected success, got $e"), identity)
      assert(ctx.hasScope(ScopeToken("accounts:read")))
      assert(!ctx.hasScope(ScopeToken("admin:all")))
    }
  }

  test("parses scopes from an `scp` array claim") {
    val c = new com.nimbusds.jwt.JWTClaimsSet.Builder(claims(scope = None))
      .claim("scp", java.util.List.of("transfers:write", "accounts:read"))
      .build()
    validator().validate(sign(c)).map { result =>
      assertEquals(
        result.map(_.scopes.map(s => s.value: String)),
        Right(Set("transfers:write", "accounts:read"))
      )
    }
  }

  test("rejects an expired token") {
    validator().validate(sign(claims(expiresIn = -10.minutes))).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("accepts a token expired within the clock-skew window") {
    validator().validate(sign(claims(expiresIn = -10.seconds))).map { result =>
      assert(result.isRight, result.toString)
    }
  }

  test("rejects a token with no typ header (it must declare at+jwt or JWT)") {
    val jwt = new com.nimbusds.jwt.SignedJWT(
      new com.nimbusds.jose.JWSHeader.Builder(
        com.nimbusds.jose.JWSAlgorithm.RS256
      )
        .keyID(signingKey.getKeyID)
        .build(),
      claims()
    )
    jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(signingKey))
    validator()
      .validate(jwt.serialize())
      .map(result =>
        assertEquals(result, Left(AuthError.InvalidToken.Rejected))
      )
  }

  test("rejects a token from the wrong issuer") {
    validator().validate(sign(claims(iss = "https://evil.example"))).map {
      result =>
        assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("rejects a token for a different audience") {
    validator().validate(sign(claims(aud = "https://other-api.example"))).map {
      result =>
        assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("rejects a token signed by an unknown key, even with a matching kid") {
    validator().validate(sign(claims(), key = rogueKey)).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("rejects HMAC-signed tokens (algorithm confusion)") {
    validator().validate(signHmac(claims())).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("rejects a token missing the required sub claim") {
    validator().validate(sign(claims(sub = null))).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("accepts an M2M token whose sub equals client_id (RFC 9068 §2.2)") {
    validator().validate(sign(claims(sub = "mobile-app"))).map { result =>
      val ctx = result.fold(e => fail(s"expected success, got $e"), identity)
      assertEquals(ctx.subject.value: String, "mobile-app")
      assertEquals(ctx.clientId.map(c => c.value: String), Some("mobile-app"))
    }
  }

  test("rejects a token whose sub claim is present but blank") {
    validator().validate(sign(claims(sub = "   "))).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("rejects a token whose typ is not accepted when restricted to at+jwt") {
    val strict =
      config.copy(acceptedTokenTypes = Set(new JOSEObjectType("at+jwt")))
    validator(strict).validate(sign(claims(), typ = JOSEObjectType.JWT)).map {
      result =>
        assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("rejects garbage that is not a JWT") {
    validator().validate("not-a-jwt").map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Malformed))
    }
  }

  test("rejects oversized tokens before parsing") {
    validator().validate("x" * (config.maxTokenLength + 1)).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Oversized))
    }
  }

  test("rejects a denylisted jti") {
    val denylist = new TokenDenylist[IO] {
      def isRevoked(tokenId: String): IO[Boolean] =
        IO.pure(tokenId == "jti-abc")
    }
    validator(denylist = denylist).validate(sign(claims())).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Revoked))
    }
  }

  test("rejects a token with no jti (jti is required by default)") {
    validator().validate(sign(claims(jti = None))).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test(
    "a token with no jti skips the denylist when jti is relaxed out of requiredClaims"
  ) {
    val cfg = config.copy(requiredClaims = Set("sub", "exp", "iat"))
    val denyAll = new TokenDenylist[IO] {
      def isRevoked(tokenId: String): IO[Boolean] = IO.pure(true)
    }
    validator(cfg, denyAll).validate(sign(claims(jti = None))).map { result =>
      assert(
        result.isRight,
        result.toString
      ) // no jti -> nothing to look up -> accepted
    }
  }

  test("fails closed with ValidationUnavailable when the key source is down") {
    val downSource = new JWKSource[SecurityContext] {
      def get(
          selector: JWKSelector,
          ctx: SecurityContext
      ): java.util.List[JWK] =
        throw new KeySourceException("JWKS endpoint unreachable")
    }
    val v = JwtValidator.fromKeySource[IO](
      config,
      downSource,
      AuthEvents.noop[IO],
      TokenDenylist.none[IO]
    )
    v.validate(sign(claims())).map { result =>
      assertEquals(result, Left(AuthError.ValidationUnavailable))
    }
  }

  test("parses a DPoP cnf.jkt binding via Nimbus") {
    validator().validate(sign(dpopBoundClaims())).map { result =>
      val ctx = result.fold(e => fail(s"expected success, got $e"), identity)
      ctx.confirmation match {
        case Some(ConfirmationClaim.DPoP(jkt)) =>
          assertEquals(jkt.value: String, dpopJkt)
        case other => fail(s"expected DPoP confirmation, got $other")
      }
    }
  }

  test("AuthConfig rejects a non-https jwksUri") {
    intercept[IllegalArgumentException] {
      config.copy(jwksUri =
        java.net.URI.create("http://auth.test.example/jwks")
      )
    }
  }

  test("AuthConfig rejects an HMAC signing algorithm") {
    intercept[IllegalArgumentException] {
      config.copy(allowedAlgorithms = Set(com.nimbusds.jose.JWSAlgorithm.HS256))
    }
  }

  test("AuthConfig rejects an empty algorithm set") {
    intercept[IllegalArgumentException](
      config.copy(allowedAlgorithms = Set.empty)
    )
  }

  test("rejects a token missing the required client_id claim (RFC 9068)") {
    val c = new com.nimbusds.jwt.JWTClaimsSet.Builder(claims())
      .claim("client_id", null)
      .build()
    validator().validate(sign(c)).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("clientId falls back to azp when client_id is not in requiredClaims") {
    val cfg = config.copy(requiredClaims =
      Set("sub", "exp", "iat")
    ) // relaxed: client_id optional
    val c = new com.nimbusds.jwt.JWTClaimsSet.Builder(claims())
      .claim("client_id", null)
      .claim("azp", "svc-account")
      .build()
    validator(cfg).validate(sign(c)).map { result =>
      assertEquals(
        result.map(_.clientId.map(id => id.value: String)),
        Right(Some("svc-account"))
      )
    }
  }

  test("rejects a not-yet-valid token (nbf in the future)") {
    val c = new com.nimbusds.jwt.JWTClaimsSet.Builder(claims())
      .notBeforeTime(
        new java.util.Date(System.currentTimeMillis() + 10.minutes.toMillis)
      )
      .build()
    validator().validate(sign(c)).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("accepts a token whose aud is a list containing this API") {
    val c = new com.nimbusds.jwt.JWTClaimsSet.Builder(claims())
      .audience(java.util.List.of("https://other-api.example", audience))
      .build()
    validator()
      .validate(sign(c))
      .map(result => assert(result.isRight, result.toString))
  }

  test("yields empty scopes when neither scope nor scp is present") {
    validator().validate(sign(claims(scope = None))).map { result =>
      assertEquals(result.map(_.scopes), Right(Set.empty[ScopeToken]))
    }
  }

  test("rejects a present-but-malformed cnf.jkt (fails closed, no downgrade)") {
    validator().validate(sign(dpopBoundClaims(jkt = "too-short"))).map {
      result =>
        assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("rejects a present-but-malformed cnf.x5t#S256 (fails closed)") {
    validator().validate(sign(mtlsBoundClaims("too-short"))).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("rejects a cnf carrying both jkt and x5t#S256") {
    val cnf = new com.nimbusds.jwt.JWTClaimsSet.Builder(claims())
      .claim("cnf", java.util.Map.of("jkt", dpopJkt, "x5t#S256", dpopJkt))
      .build()
    validator().validate(sign(cnf)).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.Rejected))
    }
  }

  test("parses an mTLS cnf.x5t#S256 binding via Nimbus") {
    validator().validate(sign(mtlsBoundClaims(dpopJkt))).map { result =>
      val ctx = result.fold(e => fail(s"expected success, got $e"), identity)
      ctx.confirmation match {
        case Some(ConfirmationClaim.MutualTls(t)) =>
          assertEquals(t.value: String, dpopJkt)
        case other => fail(s"expected MutualTls confirmation, got $other")
      }
    }
  }
}
