package auth
package dpop

import auth.dpop.{DpopConfig, DpopVerifier}

import cats.effect.IO
import cats.effect.kernel.Resource
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import java.util.{Date, UUID}
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProofUse
import com.nimbusds.oauth2.sdk.util.singleuse.{
  AlreadyUsedException,
  SingleUseChecker
}
import org.http4s.HttpApp
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.typelevel.ci.*

import scala.concurrent.duration.*

class DpopVerifierSpec extends DpopBaseSuite {
  import TestTokens.*

  private def assertDpopRejected(resp: Response[IO]): IO[Unit] = IO {
    assertEquals(resp.status, Status.Unauthorized)
    assert(
      challengeOf(resp).contains("""error="invalid_dpop_proof""""),
      challengeOf(resp)
    )
  }

  test("accepts a DPoP-bound token with a valid proof") {
    val token = sign(dpopBoundClaims())
    app().use { a =>
      for {
        resp <- a.run(
          dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
        )
        _ = assertEquals(resp.status, Status.Ok)
        body <- resp.as[String]
      } yield assertEquals(body, "user-123")
    }
  }

  test("rejects a replayed proof (same jti)") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof("GET", accountsUri.renderString, token)
    app().use { a =>
      for {
        first <- a.run(dpopRequest(token, proof))
        _ = assertEquals(first.status, Status.Ok)
        again <- a.run(dpopRequest(token, proof))
        _ <- assertDpopRejected(again)
      } yield ()
    }
  }

  test("rejects a proof whose htm does not match the request method") {
    val token = sign(dpopBoundClaims())
    app().use(
      _.run(
        dpopRequest(token, dpopProof("POST", accountsUri.renderString, token))
      ).flatMap(assertDpopRejected)
    )
  }

  test("rejects a proof whose htu does not match the request URI") {
    val token = sign(dpopBoundClaims())
    app().use(
      _.run(
        dpopRequest(
          token,
          dpopProof("GET", "https://evil.example/accounts", token)
        )
      ).flatMap(assertDpopRejected)
    )
  }

  test("rejects a stale proof") {
    val token = sign(dpopBoundClaims())
    val proof =
      dpopProof("GET", accountsUri.renderString, token, iatOffset = -10.minutes)
    app().use(_.run(dpopRequest(token, proof)).flatMap(assertDpopRejected))
  }

  test("rejects a proof whose iat is in the future") {
    val token = sign(dpopBoundClaims())
    val proof =
      dpopProof("GET", accountsUri.renderString, token, iatOffset = 10.minutes)
    app().use(_.run(dpopRequest(token, proof)).flatMap(assertDpopRejected))
  }

  test("rejects a proof whose ath hashes a different access token") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof(
      "GET",
      accountsUri.renderString,
      token,
      ath = Some(DpopVerifier.accessTokenHash("a-different-token"))
    )
    app().use(_.run(dpopRequest(token, proof)).flatMap(assertDpopRejected))
  }

  test(
    "rejects a proof signed by a key other than the one the token is bound to"
  ) {
    val token = sign(dpopBoundClaims())
    val proof =
      dpopProof("GET", accountsUri.renderString, token, key = rogueDpopKey)
    app().use(_.run(dpopRequest(token, proof)).flatMap(assertDpopRejected))
  }

  test("rejects a proof whose typ is not dpop+jwt") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof(
      "GET",
      accountsUri.renderString,
      token,
      typ = JOSEObjectType.JWT
    )
    app().use(_.run(dpopRequest(token, proof)).flatMap(assertDpopRejected))
  }

  test("rejects a missing DPoP proof header") {
    val token = sign(dpopBoundClaims())
    val req = Request[IO](Method.GET, accountsUri)
      .putHeaders(org.http4s.Header.Raw(ci"Authorization", s"DPoP $token"))
    app().use(_.run(req).flatMap(assertDpopRejected))
  }

  test("rejects multiple DPoP proof headers") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof("GET", accountsUri.renderString, token)
    val req = Request[IO](Method.GET, accountsUri).putHeaders(
      org.http4s.Header.Raw(ci"Authorization", s"DPoP $token"),
      org.http4s.Header.Raw(ci"DPoP", proof),
      org.http4s.Header.Raw(ci"DPoP", proof)
    )
    app().use(_.run(req).flatMap(assertDpopRejected))
  }

  test("rejects an oversized DPoP proof before parsing") {
    val token = sign(dpopBoundClaims())
    app().use(_.run(dpopRequest(token, "x" * 5000)).flatMap(assertDpopRejected))
  }

  test("rejects a DPoP-bound token presented as Bearer (binding downgrade)") {
    val token = sign(dpopBoundClaims())
    app().use { a =>
      a.run(bearerRequest(token)).map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        assert(
          challengeOf(resp).contains("""error="invalid_token""""),
          challengeOf(resp)
        )
      }
    }
  }

  test("rejects the DPoP scheme when the token carries no cnf.jkt binding") {
    val token = sign(claims())
    app().use(
      _.run(
        dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
      ).map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
      }
    )
  }

  test("rejects the DPoP scheme when DPoP is not enabled on the middleware") {
    val plainApp = AccessTokenAuth
      .middleware(validator, AuthEvents.noop[IO])
      .apply(routes)
      .orNotFound
    val token = sign(dpopBoundClaims())
    plainApp
      .run(
        dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
      )
      .map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        assert(
          challengeOf(resp).contains("""error="invalid_token""""),
          challengeOf(resp)
        )
      }
  }

  test("Required policy rejects plain bearer tokens") {
    val token = sign(claims())
    app(SenderConstraintPolicy.Required).use { a =>
      a.run(bearerRequest(token)).map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        assert(
          challengeOf(resp).contains("sender-constrained"),
          challengeOf(resp)
        )
      }
    }
  }

  test("Required policy accepts a DPoP-bound token with a valid proof") {
    val token = sign(dpopBoundClaims())
    app(SenderConstraintPolicy.Required).use(
      _.run(
        dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
      ).map { resp =>
        assertEquals(resp.status, Status.Ok)
      }
    )
  }

  test(
    "DpopConfig rejects a non-EC/RSA algorithm (EdDSA, unsupported by the Nimbus verifier)"
  ) {
    intercept[IllegalArgumentException](
      DpopConfig(allowedAlgorithms = Set(com.nimbusds.jose.JWSAlgorithm.EdDSA))
    )
  }

  test("the missing-credentials challenge advertises both Bearer and DPoP") {
    app().use { a =>
      a.run(Request[IO](Method.GET, accountsUri)).map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        assert(
          challengeOf(resp).contains("""Bearer realm="api""""),
          challengeOf(resp)
        )
        assert(
          challengeOf(resp).contains("""DPoP algs="ES256 PS256""""),
          challengeOf(resp)
        )
      }
    }
  }

  // -- Required proof claims: each must be present (RFC 9449 §4.2-4.3) --------

  /** Sign an arbitrary claims set as a dpop+jwt proof with the bound key, so a
    * test can omit an individual required claim (which `dpopProof` always
    * sets).
    */
  private def signProof(claims: JWTClaimsSet): String = {
    val jwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.ES256)
        .`type`(new JOSEObjectType("dpop+jwt"))
        .jwk(dpopKey.toPublicJWK)
        .build(),
      claims
    )
    jwt.sign(new ECDSASigner(dpopKey))
    jwt.serialize()
  }

  /** A proof over `token` that includes each required claim unless toggled off.
    */
  private def proofWith(
      token: String,
      jti: Boolean = true,
      htm: Boolean = true,
      htu: Boolean = true,
      iat: Boolean = true,
      ath: Boolean = true
  ): String = {
    var b = new JWTClaimsSet.Builder()
    if (jti) b = b.jwtID(UUID.randomUUID.toString)
    if (htm) b = b.claim("htm", "GET")
    if (htu) b = b.claim("htu", accountsUri.renderString)
    if (iat) b = b.issueTime(new Date())
    if (ath) b = b.claim("ath", DpopVerifier.accessTokenHash(token))
    signProof(b.build())
  }

  private def assertProofRejected(mkProof: String => String): IO[Unit] = {
    val token = sign(dpopBoundClaims())
    app().use(
      _.run(dpopRequest(token, mkProof(token))).flatMap(assertDpopRejected)
    )
  }

  test("rejects a proof with no jti") {
    assertProofRejected(t => proofWith(t, jti = false))
  }
  test("rejects a proof with no htm") {
    assertProofRejected(t => proofWith(t, htm = false))
  }
  test("rejects a proof with no htu") {
    assertProofRejected(t => proofWith(t, htu = false))
  }
  test("rejects a proof with no iat") {
    assertProofRejected(t => proofWith(t, iat = false))
  }
  test("rejects a proof with no ath (would unbind it from the access token)") {
    assertProofRejected(t => proofWith(t, ath = false))
  }

  test("sanity: proofWith with all claims present is accepted") {
    val token = sign(dpopBoundClaims())
    app().use(
      _.run(dpopRequest(token, proofWith(token))).map(r =>
        assertEquals(r.status, Status.Ok)
      )
    )
  }

  // -- Injected shared-store single-use checker (multi-node replay) -----------

  /** A trivial shared `SingleUseChecker`, standing in for a Redis-backed store:
    * two verifier instances (two "nodes") pointed at the same map see each
    * other's consumed jtis.
    */
  private def sharedChecker(): SingleUseChecker[DPoPProofUse] = {
    val seen =
      new java.util.concurrent.ConcurrentHashMap[String, java.lang.Boolean]()
    (use: DPoPProofUse) =>
      val key = use.getIssuer.getValue + ":" + use.getJWTID.getValue
      if (seen.putIfAbsent(key, java.lang.Boolean.TRUE) != null)
        throw new AlreadyUsedException("jti already used")
  }

  /** A middleware "node" whose verifier uses the supplied single-use checker
    * (or the default per-node in-memory one when `None`).
    */
  private def node(
      checker: Option[SingleUseChecker[DPoPProofUse]]
  ): Resource[IO, HttpApp[IO]] =
    DpopVerifier
      .default[IO](
        DpopConfig(),
        AuthEvents.noop[IO],
        singleUseChecker = checker
      )
      .map { verifier =>
        AccessTokenAuth
          .middleware(validator, AuthEvents.noop[IO], dpop = Some(verifier))
          .apply(routes)
          .orNotFound
      }

  test(
    "a shared single-use checker catches a proof replayed onto another node"
  ) {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof("GET", accountsUri.renderString, token)
    val shared = sharedChecker()
    val cluster = for {
      a <- node(Some(shared))
      b <- node(Some(shared))
    } yield (a, b)
    cluster.use { case (nodeA, nodeB) =>
      for {
        first <- nodeA.run(dpopRequest(token, proof))
        _ = assertEquals(first.status, Status.Ok)
        // Same proof to a *different* node: rejected, checker is shared.
        replay <- nodeB.run(dpopRequest(token, proof))
        _ <- assertDpopRejected(replay)
      } yield ()
    }
  }

  test("the default per-node checker does NOT catch a cross-node replay") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof("GET", accountsUri.renderString, token)
    val cluster = for {
      a <- node(None)
      b <- node(None)
    } yield (a, b)
    cluster.use { case (nodeA, nodeB) =>
      for {
        first <- nodeA.run(dpopRequest(token, proof))
        _ = assertEquals(first.status, Status.Ok)
        // Each node has its own in-memory checker, so node B never saw the jti —
        // the gap the injected shared-store checker closes.
        replay <- nodeB.run(dpopRequest(token, proof))
        _ = assertEquals(replay.status, Status.Ok)
      } yield ()
    }
  }
}
