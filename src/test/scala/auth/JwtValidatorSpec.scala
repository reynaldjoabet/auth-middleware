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

  test("rejects a token without jti when requireTokenId is on") {
    validator(config.copy(requireTokenId = true))
      .validate(sign(claims(jti = None)))
      .map { result =>
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

  test("clientId falls back to the azp claim when client_id is absent") {
    val c = new com.nimbusds.jwt.JWTClaimsSet.Builder(claims())
      .claim("client_id", null)
      .claim("azp", "svc-account")
      .build()
    validator().validate(sign(c)).map { result =>
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
