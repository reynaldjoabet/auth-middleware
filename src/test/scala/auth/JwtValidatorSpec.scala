package auth

import cats.effect.IO
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import munit.CatsEffectSuite
import auth.given
import scala.concurrent.duration.*

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
      assertEquals(ctx.subject, "user-123")
      assertEquals(ctx.clientId, Some("mobile-app"))
      assertEquals(ctx.scopes, Set("accounts:read", "payments:read"))
      assertEquals(ctx.tokenId, Some("jti-abc"))
    }
  }

  test("parses scopes from an `scp` array claim") {
    val c = new com.nimbusds.jwt.JWTClaimsSet.Builder(claims(scope = None))
      .claim("scp", java.util.List.of("transfers:write", "accounts:read"))
      .build()
    validator().validate(sign(c)).map { result =>
      assertEquals(
        result.map(_.scopes),
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
}
