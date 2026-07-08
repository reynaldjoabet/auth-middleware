package auth
package dpop

import auth.dpop.{DpopConfig, DpopProofValidator, DpopVerifier}

import java.util.{Date, UUID}

import scala.concurrent.duration.*

import cats.effect.IO
import com.nimbusds.jose.crypto.{ECDSASigner, RSASSASigner}
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, JWSHeader}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import munit.CatsEffectSuite

class DpopProofValidatorSpec extends CatsEffectSuite {
  import TestTokens.*

  private val validator =
    DpopProofValidator.default[IO](DpopConfig(), AuthEvents.noop[IO])

  private val accessToken = sign(dpopBoundClaims())
  private val htu = "https://api.test.example/accounts"

  /** Proof claims with each DPoP claim individually omittable. */
  private def proofClaims(
      ath: Option[String] = Some(DpopVerifier.accessTokenHash(accessToken)),
      htm: Option[String] = Some("GET"),
      htuClaim: Option[String] = Some(htu),
      jti: Option[String] = Some(UUID.randomUUID().toString)
  ): JWTClaimsSet = {
    val b = new JWTClaimsSet.Builder().issueTime(new Date())
    jti.foreach(b.jwtID)
    ath.foreach(b.claim("ath", _))
    htm.foreach(b.claim("htm", _))
    htuClaim.foreach(b.claim("htu", _))
    b.build()
  }

  /** Sign proof claims ES256, optionally omitting the header `jwk`. */
  private def signProof(
      claimsSet: JWTClaimsSet,
      includeJwk: Boolean = true
  ): String = {
    val base = new JWSHeader.Builder(JWSAlgorithm.ES256)
      .`type`(new JOSEObjectType("dpop+jwt"))
    val hb = if (includeJwk) base.jwk(dpopKey.toPublicJWK) else base
    val jwt = new SignedJWT(hb.build(), claimsSet)
    jwt.sign(new ECDSASigner(dpopKey))
    jwt.serialize()
  }

  test("accepts a fresh proof signed with its own header key") {
    validator.validate(dpopProof("GET", htu, accessToken)).map { result =>
      val claims =
        result.fold(e => fail(s"expected valid proof, got $e"), identity)
      assertEquals(claims.getStringClaim("htm"), "GET")
      assertEquals(claims.getStringClaim("htu"), htu)
      assertEquals(
        claims.getStringClaim("ath"),
        DpopVerifier.accessTokenHash(accessToken)
      )
    }
  }

  test("rejects a proof whose typ is not dpop+jwt") {
    val proof = dpopProof(
      "GET",
      htu,
      accessToken,
      typ = new JOSEObjectType("at+jwt")
    )
    validator.validate(proof).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("rejects a proof signed by a key other than its header key") {
    // header carries dpopKey's public JWK, signature is rogueDpopKey's
    val forged = {
      val good = dpopProof("GET", htu, accessToken)
      val rogue = dpopProof("GET", htu, accessToken, key = rogueDpopKey)
      good.substring(0, good.lastIndexOf('.')) +
        rogue.substring(rogue.lastIndexOf('.'))
    }
    validator.validate(forged).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("rejects an expired proof (iat older than proofMaxAge + skew)") {
    val proof = dpopProof("GET", htu, accessToken, iatOffset = -10.minutes)
    validator.validate(proof).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("rejects a proof from the future (iat beyond clock skew)") {
    val proof = dpopProof("GET", htu, accessToken, iatOffset = 10.minutes)
    validator.validate(proof).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("rejects a proof missing the jti claim") {
    val proof = dpopProof("GET", htu, accessToken, jti = null)
    validator.validate(proof).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("rejects garbage that is not a JWT") {
    validator.validate("not-a-jwt").map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Malformed))
    }
  }

  test("rejects an oversized proof") {
    val proof = dpopProof("GET", htu, accessToken) + ("A" * 8192)
    validator.validate(proof).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Malformed))
    }
  }

  test("rejects a proof missing the ath claim") {
    validator.validate(signProof(proofClaims(ath = None))).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("rejects a proof missing the htm claim") {
    validator.validate(signProof(proofClaims(htm = None))).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("rejects a proof missing the htu claim") {
    validator.validate(signProof(proofClaims(htuClaim = None))).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("rejects a proof whose header carries no jwk") {
    validator.validate(signProof(proofClaims(), includeJwk = false)).map {
      result =>
        assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("rejects a proof signed with an algorithm outside the allowlist") {
    // RS256 is asymmetric but not in DpopConfig's default {ES256, PS256}
    val jwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.RS256)
        .`type`(new JOSEObjectType("dpop+jwt"))
        .jwk(signingKey.toPublicJWK)
        .build(),
      proofClaims()
    )
    jwt.sign(new RSASSASigner(signingKey))
    validator.validate(jwt.serialize()).map { result =>
      assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
    }
  }

  test("withKeySource accepts a proof signed by the pinned key") {
    val pinned = DpopProofValidator.withKeySource[IO](
      DpopConfig(),
      new ImmutableJWKSet[SecurityContext](new JWKSet(dpopKey.toPublicJWK)),
      AuthEvents.noop[IO]
    )
    pinned.validate(dpopProof("GET", htu, accessToken)).map { result =>
      assert(result.isRight, s"expected valid proof, got $result")
    }
  }

  test(
    "withKeySource rejects a proof signed by a key other than the pinned one"
  ) {
    val pinned = DpopProofValidator.withKeySource[IO](
      DpopConfig(),
      new ImmutableJWKSet[SecurityContext](new JWKSet(dpopKey.toPublicJWK)),
      AuthEvents.noop[IO]
    )
    pinned
      .validate(dpopProof("GET", htu, accessToken, key = rogueDpopKey))
      .map { result =>
        assertEquals(result, Left(AuthError.InvalidDpopProof.Rejected))
      }
  }
}
