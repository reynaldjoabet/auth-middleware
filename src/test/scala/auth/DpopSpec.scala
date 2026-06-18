package auth

import scala.concurrent.duration.*

import cats.effect.IO
import cats.effect.kernel.Resource
import com.nimbusds.jose.JOSEObjectType
import munit.CatsEffectSuite
import org.http4s.dsl.Http4sDsl
import org.http4s.implicits.*
import org.http4s.{AuthedRoutes, HttpApp, Method, Request, Response, Status}
import org.typelevel.ci.*

import io.github.iltotore.iron.*

class DpopSpec extends CatsEffectSuite {
  import TestTokens.*

  private object dsl extends Http4sDsl[IO]
  import dsl.*

  private val accountsUri = uri"https://api.test.example/accounts"

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

  private def app(
      policy: SenderConstraintPolicy = SenderConstraintPolicy.EnforceWhenBound
  ): Resource[IO, HttpApp[IO]] =
    DpopVerifier.default[IO](DpopConfig(), AuthEvents.noop[IO]).map {
      verifier =>
        BearerAuth
          .middleware(
            validator,
            AuthEvents.noop[IO],
            senderConstraint = policy,
            dpop = Some(verifier)
          )
          .apply(routes)
          .orNotFound
    }

  private def dpopRequest(token: String, proof: String): Request[IO] =
    Request[IO](Method.GET, accountsUri)
      .putHeaders(
        org.http4s.Header.Raw(ci"Authorization", s"DPoP $token"),
        org.http4s.Header.Raw(ci"DPoP", proof)
      )

  private def bearerRequest(token: String): Request[IO] =
    Request[IO](Method.GET, accountsUri)
      .putHeaders(org.http4s.Header.Raw(ci"Authorization", s"Bearer $token"))

  private def assertDpopRejected(resp: Response[IO]): IO[Unit] = IO {
    assertEquals(resp.status, Status.Unauthorized)
    val challenge =
      resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
    assert(challenge.contains("""error="invalid_dpop_proof""""), challenge)
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
        val challenge =
          resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
        assert(challenge.contains("""error="invalid_token""""), challenge)
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
        val challenge =
          resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
        assert(challenge.contains("""error="invalid_token""""), challenge)
      }
  }

  test("Required policy rejects plain bearer tokens") {
    val token = sign(claims())
    app(SenderConstraintPolicy.Required).use { a =>
      a.run(bearerRequest(token)).map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        val challenge =
          resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
        assert(challenge.contains("sender-constrained"), challenge)
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
        val challenge =
          resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
        assert(challenge.contains("""Bearer realm="api""""), challenge)
        assert(challenge.contains("""DPoP algs="ES256 PS256""""), challenge)
      }
    }
  }
}
