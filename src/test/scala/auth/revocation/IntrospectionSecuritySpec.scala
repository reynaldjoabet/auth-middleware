package auth
package revocation

import java.time.Instant
import java.util.{Base64, Date}
import java.util.concurrent.atomic.AtomicReference

import scala.concurrent.duration.*

import cats.effect.IO
import cats.syntax.all.*

import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.{ECDSAVerifier, RSASSASigner}
import com.nimbusds.jose.jwk.{Curve, JWKSet, RSAKey}
import com.nimbusds.jose.jwk.gen.{ECKeyGenerator, RSAKeyGenerator}
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import io.circe.Json
import munit.CatsEffectSuite
import org.http4s.{HttpApp, Request, Response, Status, UrlForm}
import org.http4s.client.Client
import org.http4s.implicits.*
import org.typelevel.ci.*

/**
  * The introspection client's two hardenings against a fake authorization server:
  *
  *   - `private_key_jwt` (RFC 7523 §2.2), with the audience and typing rules of RFC 10070
  *   - signed introspection responses (RFC 9701), trusted only once verified
  */
class IntrospectionSecuritySpec extends CatsEffectSuite {

  private val Issuer   = "https://as.test.example"
  private val ClientId = "rs-client"
  private val Endpoint = uri"https://as.test.example/oauth2/introspect"

  // The authorization server signs responses; the resource server signs assertions.
  private val asKey: RSAKey = new RSAKeyGenerator(2048).keyID("as-1").generate()
  private val rsKey         = new ECKeyGenerator(Curve.P_256).keyID("rs-1").generate()
  private val otherKey      = new RSAKeyGenerator(2048).keyID("as-1").generate()

  private val asKeys = new ImmutableJWKSet[SecurityContext](new JWKSet(asKey.toPublicJWK))

  /**
    * Records what it receives and answers with `body` as `contentType`.
    */
  private final class FakeAs(body: => String, contentType: String) {

    val received = new AtomicReference[Option[(Request[IO], Map[String, String])]](None)

    val client: Client[IO] = Client.fromHttpApp(HttpApp[IO] { req =>
      req.as[UrlForm].flatMap { form =>
        IO(
          received.set(Some((req, form.values.view.mapValues(_.headOption.getOrElse("")).toMap)))
        ) *>
          IO.pure(
            Response[IO](Status.Ok)
              .withEntity(body)
              .putHeaders(org.http4s.Header.Raw(ci"Content-Type", contentType))
          )
      }
    })

    def form: Map[String, String] = received.get.fold(Map.empty)(_._2)

    def header(name: String): Option[String] =
      received.get.flatMap(_._1.headers.get(CIString(name)).map(_.head.value))

  }

  private def signedResponse(
      active: Boolean,
      key: RSAKey = asKey,
      typ: String = "token-introspection+jwt",
      iss: String = Issuer,
      aud: String = ClientId,
      iat: Instant = Instant.now(),
      introspection: Boolean = true
  ): String = {
    val claims = new JWTClaimsSet.Builder().issuer(iss).audience(aud).issueTime(Date.from(iat))
    if (introspection) {
      val _ = claims.claim(
        "token_introspection",
        java.util.Map.of("active", java.lang.Boolean.valueOf(active))
      )
    }
    val jwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.RS256)
        .`type`(new JOSEObjectType(typ))
        .keyID(key.getKeyID)
        .build(),
      claims.build()
    )
    jwt.sign(new RSASSASigner(key))
    jwt.serialize()
  }

  private def introspection(
      as: FakeAs,
      privateKey: Boolean = false,
      signed: Boolean = false
  ): IO[TokenIntrospection[IO]] =
    TokenIntrospection.http4s[IO](
      TokenIntrospection.IntrospectionConfig(
        endpoint = Endpoint,
        clientId = ClientId,
        clientSecret = if (privateKey) "" else "s3cret",
        cacheTtl = Duration.Zero,
        // A cold JVM's first call (key loading, signing, the HTTP stack) can
        // take more than the 2 s default, which would read as Unavailable.
        requestTimeout = 10.seconds,
        privateKeyJwt = Option.when(privateKey)(PrivateKeyJwt(rsKey, Issuer)),
        jwtResponse = Option.when(signed)(
          JwtIntrospectionResponse(Issuer, Set("https://api.test.example"), asKeys)
        )
      ),
      as.client
    )

  private def payload(jwt: String): Json =
    io.circe.jawn
      .parse(String(Base64.getUrlDecoder.decode(jwt.split('.')(1)), "UTF-8"))
      .fold(e => fail(e.getMessage), identity)

  private val plainActive = """{"active":true,"sub":"u-1"}"""

  // --- RFC 7523 / RFC 10070: private_key_jwt -----------------------------------

  test("private_key_jwt sends a signed assertion instead of a client secret") {
    val as = new FakeAs(plainActive, "application/json")
    introspection(as, privateKey = true).flatMap(_.check("tok")).map { result =>
      assertEquals(result, TokenIntrospection.Result.Active)
      assertEquals(as.header("Authorization"), None, "no client secret in a Basic header")
      assertEquals(as.form.get("client_id"), Some(ClientId))
      assertEquals(as.form.get("client_assertion_type"), Some(PrivateKeyJwt.AssertionType))
      assertEquals(as.form.get("token"), Some("tok"))
    }
  }

  test("the assertion: signed by our key, typed, iss = sub = client_id, aud the issuer alone (RFC 10070)") {
    val as = new FakeAs(plainActive, "application/json")
    introspection(as, privateKey = true).flatMap(_.check("tok")).map { _ =>
      val raw = as.form("client_assertion")
      val jwt = SignedJWT.parse(raw)
      assert(jwt.verify(new ECDSAVerifier(rsKey.toECPublicKey)), "signature by the registered key")
      assertEquals(jwt.getHeader.getType.getType, "client-authentication+jwt")
      assertEquals(jwt.getHeader.getAlgorithm, JWSAlgorithm.ES256)
      val c = jwt.getJWTClaimsSet
      assertEquals(c.getIssuer, ClientId)
      assertEquals(c.getSubject, ClientId)
      // The sole audience value, as a string: never an array, never the endpoint URL.
      assertEquals(payload(raw).hcursor.downField("aud").focus, Some(Json.fromString(Issuer)))
      assert(Option(c.getJWTID).exists(_.nonEmpty))
      val lifetime = c.getExpirationTime.getTime - c.getIssueTime.getTime
      assert(lifetime > 0 && lifetime <= 60_000, s"lifetime $lifetime ms")
    }
  }

  test("every request gets a fresh assertion: a new jti each time") {
    val as = new FakeAs(plainActive, "application/json")
    introspection(as, privateKey = true).flatMap { i =>
      (
        i.check("a") *> IO(as.form("client_assertion")),
        i.check("b") *> IO(as.form("client_assertion"))
      )
        .mapN((first, second) =>
          assertNotEquals(
            SignedJWT.parse(first).getJWTClaimsSet.getJWTID,
            SignedJWT.parse(second).getJWTClaimsSet.getJWTID
          )
        )
    }
  }

  test(
    "private_key_jwt refuses a public key, and exactly one client auth is required"
  ) {
    val _ = intercept[IllegalArgumentException](PrivateKeyJwt(rsKey.toPublicJWK, Issuer))
    val _ = intercept[IllegalArgumentException](
      TokenIntrospection.IntrospectionConfig(
        Endpoint,
        ClientId,
        "s3cret",
        privateKeyJwt = Some(PrivateKeyJwt(rsKey, Issuer))
      )
    )
    intercept[IllegalArgumentException](TokenIntrospection.IntrospectionConfig(Endpoint, ClientId))
  }

  // --- RFC 9701: signed responses ----------------------------------------------

  test("a signed response is asked for, and a verified one is believed") {
    val as = new FakeAs(signedResponse(active = true), JwtIntrospectionResponse.MediaType)
    for {
      i        <- introspection(as, signed = true)
      active   <- i.check("tok")
      _         = assertEquals(as.header("Accept"), Some(JwtIntrospectionResponse.MediaType))
      _         = assertEquals(active, TokenIntrospection.Result.Active)
      inactive <- introspection(
                    new FakeAs(signedResponse(active = false), JwtIntrospectionResponse.MediaType),
                    signed = true
                  )
                    .flatMap(_.check("tok"))
    } yield assertEquals(inactive, TokenIntrospection.Result.Inactive)
  }

  test("aud may name this service by client id or by its audience") {
    introspection(
      new FakeAs(
        signedResponse(active = true, aud = "https://api.test.example"),
        JwtIntrospectionResponse.MediaType
      ),
      signed = true
    )
      .flatMap(_.check("tok"))
      .map(r => assertEquals(r, TokenIntrospection.Result.Active))
  }

  test("an answer that cannot be verified is no answer: Unavailable, so the request fails closed") {
    val cases = List(
      "plain JSON, Accept ignored"  -> plainActive,
      "signed by another key"       -> signedResponse(active = true, key = otherKey),
      "an access token's typ"       -> signedResponse(active = true, typ = "at+jwt"),
      "another issuer"              -> signedResponse(active = true, iss = "https://evil.example"),
      "for another resource server" -> signedResponse(active = true, aud = "someone-else"),
      "stale iat (replayed)"        -> signedResponse(
        active = true,
        iat = Instant.now().minusSeconds(3600)
      ),
      "iat in the future"            -> signedResponse(active = true, iat = Instant.now().plusSeconds(3600)),
      "no token_introspection claim" -> signedResponse(active = true, introspection = false),
      "not a JWT at all"             -> "garbage"
    )
    cases
      .traverse { (name, body) =>
        introspection(new FakeAs(body, JwtIntrospectionResponse.MediaType), signed = true)
          .flatMap(_.check("tok"))
          .map(name -> _)
      }
      .map(
        _.foreach((name, result) =>
          assertEquals(result, TokenIntrospection.Result.Unavailable, name)
        )
      )
  }

}
