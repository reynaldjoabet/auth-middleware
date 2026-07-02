package auth

import cats.effect.IO
import com.nimbusds.jose.JOSEObjectType
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
    val plainApp = BearerAuth
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
}
