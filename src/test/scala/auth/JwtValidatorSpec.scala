package auth

import scala.concurrent.duration.*

import cats.effect.IO
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.{JWK, JWKSelector}
import com.nimbusds.jose.{JOSEObjectType, KeySourceException}
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

  test(
    "rejects a token without jti when requireTokenId is on (jti not in requiredClaims)"
  ) {
    // isolate the requireTokenId knob: drop jti from requiredClaims so Nimbus
    // doesn't reject first, leaving the requireTokenId check to produce MissingTokenId.
    val cfg = config.copy(
      requiredClaims = Set("sub", "exp", "iat"),
      requireTokenId = true
    )
    validator(cfg).validate(sign(claims(jti = None))).map { result =>
      assertEquals(result, Left(AuthError.InvalidToken.MissingTokenId))
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

  test("drops a malformed cnf.jkt (no sender-constraint binding)") {
    validator().validate(sign(dpopBoundClaims(jkt = "too-short"))).map {
      result =>
        assertEquals(result.map(_.confirmation), Right(None))
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
