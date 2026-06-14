package auth

import java.net.URLEncoder
import java.nio.charset.StandardCharsets

import cats.effect.IO
import munit.CatsEffectSuite
import org.http4s.dsl.Http4sDsl
import org.http4s.implicits.*
import org.http4s.{AuthedRoutes, Header, Method, Request, Status}
import org.typelevel.ci.*

import io.github.iltotore.iron.*

class MtlsSpec extends CatsEffectSuite {
  import TestTokens.*

  private object dsl extends Http4sDsl[IO]
  import dsl.*

  private val clientCert =
    Mtls.parsePem(clientCertPem).getOrElse(fail("test cert must parse"))
  private val x5tS256 = Mtls.thumbprint(clientCert)

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
  ) =
    BearerAuth
      .middleware(
        validator,
        AuthEvents.noop[IO],
        senderConstraint = policy,
        clientCertificates = Some(ClientCertificates.fromForwardedHeader[IO]())
      )
      .apply(routes)
      .orNotFound

  private def request(token: String, certPem: Option[String]): Request[IO] = {
    val base = Request[IO](Method.GET, uri"/accounts")
      .putHeaders(Header.Raw(ci"Authorization", s"Bearer $token"))
    certPem.fold(base) { pem =>
      base.putHeaders(
        Header.Raw(
          ci"X-Forwarded-Client-Cert",
          URLEncoder.encode(pem, StandardCharsets.UTF_8)
        )
      )
    }
  }

  test(
    "accepts a certificate-bound token when the matching certificate is presented"
  ) {
    val token = sign(mtlsBoundClaims(x5tS256))
    app().run(request(token, Some(clientCertPem))).flatMap { resp =>
      assertEquals(resp.status, Status.Ok)
      resp.as[String].assertEquals("user-123")
    }
  }

  test("rejects a certificate-bound token when no certificate is presented") {
    val token = sign(mtlsBoundClaims(x5tS256))
    app().run(request(token, None)).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
      val challenge =
        resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")
      assert(challenge.contains("""error="invalid_token""""), challenge)
    }
  }

  test(
    "rejects a certificate-bound token presented with a different certificate"
  ) {
    val token = sign(mtlsBoundClaims(x5tS256))
    app().run(request(token, Some(otherCertPem))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
    }
  }

  test(
    "rejects a certificate-bound token when no certificate source is configured"
  ) {
    val noMtlsApp =
      BearerAuth
        .middleware(validator, AuthEvents.noop[IO])
        .apply(routes)
        .orNotFound
    val token = sign(mtlsBoundClaims(x5tS256))
    noMtlsApp.run(request(token, Some(clientCertPem))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
    }
  }

  test("an unparseable forwarded certificate fails closed") {
    val token = sign(mtlsBoundClaims(x5tS256))
    val req = request(token, None)
      .putHeaders(Header.Raw(ci"X-Forwarded-Client-Cert", "not-a-certificate"))
    app().run(req).map(resp => assertEquals(resp.status, Status.Unauthorized))
  }

  test("Required policy is satisfied by an mTLS-bound token") {
    val token = sign(mtlsBoundClaims(x5tS256))
    app(SenderConstraintPolicy.Required)
      .run(request(token, Some(clientCertPem)))
      .map { resp =>
        assertEquals(resp.status, Status.Ok)
      }
  }
}
