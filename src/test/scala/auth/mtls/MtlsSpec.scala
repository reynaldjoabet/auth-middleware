package auth
package mtls

import java.net.URLEncoder
import java.nio.charset.StandardCharsets

import cats.effect.IO
import cats.syntax.all.*

import com.comcast.ip4s.*
import auth.accesstoken.*
import auth.revocation.TokenDenylist
import io.github.iltotore.iron.*
import munit.CatsEffectSuite
import org.http4s.dsl.Http4sDsl
import org.http4s.implicits.*
import org.http4s.AuthedRoutes
import org.http4s.Header
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.typelevel.ci.*

class MtlsSpec extends CatsEffectSuite {

  import TestTokens.*

  private object dsl extends Http4sDsl[IO]
  import dsl.*

  private val clientCert =
    Mtls.parsePem(clientCertPem).getOrElse(fail("test cert must parse"))

  private val x5tS256 = Mtls.thumbprint(clientCert)

  private val validator =
    AccessTokenValidator.withKeySource[IO](
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
    AccessTokenAuth
      .middleware(
        validator,
        AuthEvents.noop[IO],
        senderConstraint = policy,
        clientCertificates = Some(ClientCertificates.fromForwardedHeader[IO](trustedProxies))
      )
      .apply(routes)
      .orNotFound

  private val trustedProxies = Mtls.parseCidrs("10.0.0.0/8, fd00::/8").fold(fail(_), identity)

  // The TCP peer the request arrived from: by default the proxy.
  private def from(peer: String): Request.Connection =
    Request.Connection(
      local = SocketAddress(ipv4"10.9.9.9", port"8080"),
      remote = SocketAddress(IpAddress.fromString(peer).getOrElse(fail(peer)), port"40000"),
      secure = false
    )

  private def request(
      token: String,
      certPem: Option[String],
      peer: Option[String] = Some("10.1.2.3")
  ): Request[IO] = {
    val base = peer
      .fold(Request[IO](Method.GET, uri"/accounts"))(p =>
        Request[IO](Method.GET, uri"/accounts").withAttribute(Request.Keys.ConnectionInfo, from(p))
      )
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
      AccessTokenAuth
        .middleware(validator, AuthEvents.noop[IO])
        .apply(routes)
        .orNotFound
    val token = sign(mtlsBoundClaims(x5tS256))
    noMtlsApp.run(request(token, Some(clientCertPem))).map { resp =>
      assertEquals(resp.status, Status.Unauthorized)
    }
  }

  test("accepts a certificate in HAProxy's forwarding format (deploy/haproxy/haproxy.cfg)") {
    // HAProxy builds the header from the raw DER: one unwrapped base64 line,
    // percent-encoded (+ / = included), between URL-encoded PEM armour.
    val base64       = java.util.Base64.getEncoder.encodeToString(clientCert.getEncoded)
    val haproxyValue =
      "-----BEGIN%20CERTIFICATE-----%0A" +
        base64.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D") +
        "%0A-----END%20CERTIFICATE-----%0A"
    val token = sign(mtlsBoundClaims(x5tS256))
    app()
      .run(
        Request[IO](Method.GET, uri"/accounts")
          .withAttribute(Request.Keys.ConnectionInfo, from("10.1.2.3"))
          .putHeaders(
            Header.Raw(ci"Authorization", s"Bearer $token"),
            Header.Raw(ci"X-Forwarded-Client-Cert", haproxyValue)
          )
      )
      .map(r => assertEquals(r.status, Status.Ok))
  }

  test("an unparseable forwarded certificate fails closed") {
    val token = sign(mtlsBoundClaims(x5tS256))
    val req   = request(token, None)
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

  test(
    "accepts a certificate-bound token via the TLS session (fromTlsSession)"
  ) {
    val tlsApp = AccessTokenAuth
      .middleware(
        validator,
        AuthEvents.noop[IO],
        clientCertificates = Some(ClientCertificates.fromTlsSession[IO])
      )
      .apply(routes)
      .orNotFound
    val session = org.http4s.server.SecureSession(
      "sid",
      "TLS_AES_128_GCM_SHA256",
      128,
      List(clientCert)
    )
    val req = Request[IO](Method.GET, uri"/accounts")
      .putHeaders(
        Header
          .Raw(ci"Authorization", s"Bearer ${sign(mtlsBoundClaims(x5tS256))}")
      )
      .withAttribute(
        org.http4s.server.ServerRequestKeys.SecureSession,
        Option(session)
      )
    tlsApp.run(req).flatMap { resp =>
      assertEquals(resp.status, Status.Ok)
      resp.as[String].assertEquals("user-123")
    }
  }

  // --- RFC 4632: the header only from trusted proxies -------------------------

  private def boundRequest(peer: Option[String]): Request[IO] =
    request(sign(mtlsBoundClaims(x5tS256)), Some(clientCertPem), peer)

  private def status(req: Request[IO]): IO[Status] =
    app().run(req).map((r: Response[IO]) => r.status)

  test("the forwarded certificate is honoured from a trusted proxy, IPv4 or IPv6") {
    List(Some("10.1.2.3"), Some("fd00::1"), Some("::ffff:10.1.2.3"))
      .traverse(peer => status(boundRequest(peer)).map(peer -> _))
      .map(_.foreach((peer, s) => assertEquals(s, Status.Ok, s"peer $peer")))
  }

  test(
    "from any other peer, or with no known peer, the header is ignored and binding fails closed"
  ) {
    List(
      Some("203.0.113.7"),
      Some("11.0.0.1"),
      Some("2001:db8::1"),
      Some("::ffff:203.0.113.7"),
      None
    )
      .traverse(peer => status(boundRequest(peer)).map(peer -> _))
      .map(_.foreach((peer, s) => assertEquals(s, Status.Unauthorized, s"peer $peer")))
  }

  test("trusted proxies: CIDR blocks and bare addresses parse; garbage is named") {
    assertEquals(Mtls.parseCidrs("").map(_.size), Right(0))
    assertEquals(Mtls.parseCidrs("10.0.0.0/8,192.168.1.10  fd00::/8").map(_.size), Right(3))
    assert(Mtls.isTrusted(ipv4"192.168.1.10", Mtls.parseCidrs("192.168.1.10").toOption.get))
    assert(!Mtls.isTrusted(ipv4"192.168.1.11", Mtls.parseCidrs("192.168.1.10").toOption.get))
    assertEquals(
      Mtls.parseCidrs("10.0.0.0/8, nope"),
      Left("'nope' is not a CIDR block or IP address")
    )
  }

  test("a forwarded-certificate source with no trusted proxies is refused") {
    intercept[IllegalArgumentException](ClientCertificates.fromForwardedHeader[IO](Nil))
  }

}
