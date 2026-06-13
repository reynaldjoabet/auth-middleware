package auth

import cats.effect.IO
import com.nimbusds.jose.JOSEObjectType
import munit.CatsEffectSuite
import org.http4s.AuthedRoutes
import org.http4s.HttpApp
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.http4s.dsl.Http4sDsl
import org.http4s.implicits.*
import org.typelevel.ci.*
import auth.given

import scala.concurrent.duration.*

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
    case GET -> Root / "accounts" as ctx => Ok(ctx.subject)
  }

  private def app(
      policy: SenderConstraintPolicy = SenderConstraintPolicy.EnforceWhenBound
  ): IO[HttpApp[IO]] =
    DpopReplayCache.inMemory[IO]().map { cache =>
      val verifier =
        DpopVerifier.default[IO](DpopConfig(), cache, AuthEvents.noop[IO])
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

  private def assertDpopRejected(resp: Response[IO]): IO[Unit] = {
    assertEquals(resp.status, Status.Unauthorized)
    val challenge =
      resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
    assert(challenge.contains("""error="invalid_dpop_proof""""), challenge)
    IO.unit
  }

  test("accepts a DPoP-bound token with a valid proof") {
    val token = sign(dpopBoundClaims())
    for {
      a <- app()
      resp <- a.run(
        dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
      )
      _ = assertEquals(resp.status, Status.Ok)
      body <- resp.as[String]
    } yield assertEquals(body, "user-123")
  }

  test("rejects a replayed proof (same jti)") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof("GET", accountsUri.renderString, token)
    for {
      a <- app()
      first <- a.run(dpopRequest(token, proof))
      _ = assertEquals(first.status, Status.Ok)
      again <- a.run(dpopRequest(token, proof))
      _ <- assertDpopRejected(again)
    } yield ()
  }

  test("rejects a proof whose htm does not match the request method") {
    val token = sign(dpopBoundClaims())
    for {
      a <- app()
      resp <- a.run(
        dpopRequest(token, dpopProof("POST", accountsUri.renderString, token))
      )
      _ <- assertDpopRejected(resp)
    } yield ()
  }

  test("rejects a proof whose htu does not match the request URI") {
    val token = sign(dpopBoundClaims())
    for {
      a <- app()
      resp <- a.run(
        dpopRequest(
          token,
          dpopProof("GET", "https://evil.example/accounts", token)
        )
      )
      _ <- assertDpopRejected(resp)
    } yield ()
  }

  test("rejects a stale proof") {
    val token = sign(dpopBoundClaims())
    val proof =
      dpopProof("GET", accountsUri.renderString, token, iatOffset = -10.minutes)
    for {
      a <- app()
      resp <- a.run(dpopRequest(token, proof))
      _ <- assertDpopRejected(resp)
    } yield ()
  }

  test("rejects a proof whose ath hashes a different access token") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof(
      "GET",
      accountsUri.renderString,
      token,
      ath = Some(DpopVerifier.accessTokenHash("a-different-token"))
    )
    for {
      a <- app()
      resp <- a.run(dpopRequest(token, proof))
      _ <- assertDpopRejected(resp)
    } yield ()
  }

  test(
    "rejects a proof signed by a key other than the one the token is bound to"
  ) {
    val token = sign(dpopBoundClaims()) // bound to dpopKey
    val proof =
      dpopProof("GET", accountsUri.renderString, token, key = rogueDpopKey)
    for {
      a <- app()
      resp <- a.run(dpopRequest(token, proof))
      _ <- assertDpopRejected(resp)
    } yield ()
  }

  test("rejects a proof whose typ is not dpop+jwt") {
    val token = sign(dpopBoundClaims())
    val proof =
      dpopProof(
        "GET",
        accountsUri.renderString,
        token,
        typ = JOSEObjectType.JWT
      )
    for {
      a <- app()
      resp <- a.run(dpopRequest(token, proof))
      _ <- assertDpopRejected(resp)
    } yield ()
  }

  test("rejects a DPoP-bound token presented as Bearer (binding downgrade)") {
    val token = sign(dpopBoundClaims())
    for {
      a <- app()
      resp <- a.run(bearerRequest(token))
      _ = assertEquals(resp.status, Status.Unauthorized)
      challenge = resp.headers
        .get(ci"WWW-Authenticate")
        .map(_.head.value)
        .getOrElse("")
      _ = assert(challenge.contains("""error="invalid_token""""), challenge)
    } yield ()
  }

  test("rejects the DPoP scheme when the token carries no cnf.jkt binding") {
    val token = sign(claims())
    for {
      a <- app()
      resp <- a.run(
        dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
      )
      _ = assertEquals(resp.status, Status.Unauthorized)
    } yield ()
  }

  test("rejects a DPoP token without a DPoP proof header") {
    val token = sign(dpopBoundClaims())
    val req = Request[IO](Method.GET, accountsUri)
      .putHeaders(org.http4s.Header.Raw(ci"Authorization", s"DPoP $token"))
    for {
      a <- app()
      resp <- a.run(req)
      _ <- assertDpopRejected(resp)
    } yield ()
  }

  test("Required policy rejects plain bearer tokens") {
    val token = sign(claims())
    for {
      a <- app(SenderConstraintPolicy.Required)
      resp <- a.run(bearerRequest(token))
      _ = assertEquals(resp.status, Status.Unauthorized)
      challenge = resp.headers
        .get(ci"WWW-Authenticate")
        .map(_.head.value)
        .getOrElse("")
      _ = assert(challenge.contains("sender-constrained"), challenge)
    } yield ()
  }

  test("Required policy accepts a DPoP-bound token with a valid proof") {
    val token = sign(dpopBoundClaims())
    for {
      a <- app(SenderConstraintPolicy.Required)
      resp <- a.run(
        dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
      )
      _ = assertEquals(resp.status, Status.Ok)
    } yield ()
  }

  test("the missing-credentials challenge advertises both Bearer and DPoP") {
    for {
      a <- app()
      resp <- a.run(Request[IO](Method.GET, accountsUri))
      _ = assertEquals(resp.status, Status.Unauthorized)
      challenge = resp.headers
        .get(ci"WWW-Authenticate")
        .map(_.head.value)
        .getOrElse("")
      _ = assert(challenge.contains("""Bearer realm="api""""), challenge)
      _ = assert(
        challenge.contains("""DPoP algs="ES256 EdDSA PS256""""),
        challenge
      )
    } yield ()
  }
}
