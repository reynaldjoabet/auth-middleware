package auth

import java.util.{Date, UUID}

import cats.effect.IO
import cats.syntax.all.*

import auth.accesstoken.AccessTokenValidator
import auth.revocation.TokenDenylist
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jwt.JWTClaimsSet
import munit.CatsEffectSuite
import org.http4s.{AuthedRoutes, Header, Headers, Method, Request, Response, Status, Uri}
import org.http4s.dsl.io.*
import org.typelevel.ci.CIString

/**
  * Claims and headers from the RFCs a resource server consumes:
  *
  *   - RFC 8693 `act`: delegation, parsed and fail-closed when malformed
  *   - RFC 9396 `authorization_details`: per-route grants, one entry meeting the whole requirement
  *   - RFC 9068 §4 / RFC 8725 §3.11 / RFC 9701 §8.1: the access token's `typ`
  */
class RfcClaimsSpec extends CatsEffectSuite {

  import TestTokens.*

  private val validator =
    AccessTokenValidator
      .withKeySource[IO](config, keySource, AuthEvents.noop[IO], TokenDenylist.none[IO])

  private def token(extra: (String, AnyRef)*): JWTClaimsSet = {
    val b = new JWTClaimsSet.Builder(claims(jti = Some(UUID.randomUUID().toString)))
      .issueTime(new Date())
    extra.foreach((k, v) => b.claim(k, v))
    b.build()
  }

  private def json(s: String): AnyRef = JSONObjectUtils.parse(s"""{"v":$s}""").get("v")

  private def validate(
      claimsSet: JWTClaimsSet,
      typ: JOSEObjectType = new JOSEObjectType("at+jwt")
  ) =
    validator.validate(sign(claimsSet, typ = typ))

  // --- RFC 8693 act -----------------------------------------------------------

  test("act: the current actor and the prior chain are read; prior actors are kept for audit") {
    val act =
      json("""{"sub":"https://service16.example","act":{"sub":"https://service77.example"}}""")
    validate(token("act" -> act)).map {
      case Right(ctx) =>
        assert(ctx.isDelegated)
        assertEquals(ctx.actor.map(_.id), Some("https://service16.example"))
        assertEquals(
          ctx.actor.toList.flatMap(_.chain).map(_.id),
          List("https://service16.example", "https://service77.example")
        )
        assert(
          ctx.toString.contains("actor=https://service16.example <- https://service77.example")
        )
      case Left(e) => fail(s"rejected: $e")
    }
  }

  test("act: an actor identified by client_id alone is accepted (RFC 8693 §4.3)") {
    validate(token("act" -> json("""{"client_id":"batch-service"}""")))
      .map(r => assertEquals(r.map(_.actor.map(_.id)), Right(Some("batch-service"))))
  }

  test("act: malformed values fail the token rather than hide who is acting") {
    val deep = (1 to Actor.MaxDepth + 1).foldLeft("""{"sub":"s0"}""")((inner, i) =>
      s"""{"sub":"s$i","act":$inner}"""
    )
    List(
      json(""""a string""""),
      json("""{"iss":"https://issuer.example"}"""),
      json("""{"sub":"  "}"""),
      json(deep)
    ).traverse(act => validate(token("act" -> act)))
      .map(_.foreach(r => assert(r.isLeft, s"accepted: $r")))
  }

  test("no act: not delegated") {
    validate(token()).map(r => assertEquals(r.map(_.isDelegated), Right(false)))
  }

  // --- RFC 9396 authorization_details ----------------------------------------

  private def payment =
    """{"type":"payment_initiation","actions":["initiate","status"],
       "locations":["https://api.bank.example/payments"],
       "instructedAmount":{"currency":"EUR","amount":"123.50"}}"""

  private def customers =
    """[{"type":"customer_information","actions":["read"],"datatypes":["contacts"]},
        {"type":"customer_information","actions":["write"],"datatypes":["photos"]}]"""

  private def app(requirement: AuthorizationDetailRequirement) =
    AccessTokenAuth
      .middleware[IO](validator, AuthEvents.noop[IO])(
        AccessTokenAuth.requireAuthorizationDetail[IO](requirement)(
          AuthedRoutes.of[AuthContext, IO] { case GET -> Root / "op" as ctx =>
            // The handler enforces the API-specific fields of the matched entry.
            Ok(requirement.firstMatch(ctx).fold("")(_.json))
          }
        )
      )
      .orNotFound

  private def call(requirement: AuthorizationDetailRequirement, details: String): IO[Response[IO]] =
    app(requirement).run(
      Request[IO](Method.GET, Uri.unsafeFromString("/op")).withHeaders(
        Headers(
          Header.Raw(
            CIString("Authorization"),
            s"Bearer ${sign(token("authorization_details" -> json(details)))}"
          )
        )
      )
    )

  private def initiate = AuthorizationDetailRequirement(
    "payment_initiation",
    actions = Set("initiate"),
    locations = Set("https://api.bank.example/payments")
  )

  test(
    "authorization_details: a matching entry lets the request through, its fields reach the handler"
  ) {
    call(initiate, s"[$payment]").flatMap { r =>
      assertEquals(r.status, Status.Ok)
      r.as[String].map(body => assert(body.contains("\"amount\":\"123.50\""), body))
    }
  }

  test("authorization_details: a grant for another location or action is 403 insufficient_scope") {
    List(
      initiate.copy(locations = Set("https://other-rs.example")),
      initiate.copy(actions = Set("cancel")),
      initiate.copy(`type` = "account_information")
    ).traverse(req => call(req, s"[$payment]"))
      .map(_.foreach { r =>
        assertEquals(r.status, Status.Forbidden)
        val challenge = r.headers.get(CIString("WWW-Authenticate")).fold("")(_.head.value)
        assert(challenge.contains("insufficient_scope"), challenge)
        assert(!challenge.contains("scope=\""), "no scope a client could ask for instead")
      })
  }

  test("authorization_details: separate entries are separate grants (RFC 9396 §2.2)") {
    val readContacts = AuthorizationDetailRequirement(
      "customer_information",
      Set("read"),
      datatypes = Set("contacts")
    )
    val writeContacts = readContacts.copy(actions = Set("write"))
    for {
      allowed <- call(readContacts, customers)
      denied  <- call(writeContacts, customers)
    } yield {
      assertEquals(allowed.status, Status.Ok)
      assertEquals(denied.status, Status.Forbidden, "write was granted for photos, not contacts")
    }
  }

  test("authorization_details: malformed values fail the token") {
    List(
      """{"type":"payment_initiation"}""",
      """[{"actions":["initiate"]}]""",
      """[{"type":"payment_initiation","actions":"initiate"}]""",
      """[{"type":"payment_initiation","actions":[1]}]""",
      """["payment_initiation"]"""
    ).traverse(d => validate(token("authorization_details" -> json(d))))
      .map(_.foreach(r => assert(r.isLeft, s"accepted: $r")))
  }

  // --- typ (RFC 9068 §4, RFC 8725 §3.11, RFC 9701 §8.1) ------------------------

  test("typ: a token without typ is rejected (RFC 8725 §3.11)") {
    validate(token(), typ = null).map(r => assert(r.isLeft, s"accepted: $r"))
  }

  test("typ: at+jwt and its full media-type form application/at+jwt are both accepted") {
    List("at+jwt", "application/at+jwt", "AT+JWT")
      .traverse(t => validate(token(), new JOSEObjectType(t)).map(t -> _))
      .map(_.foreach((t, r) => assert(r.isRight, s"typ $t rejected: $r")))
  }

  test(
    "typ: other JWT types are rejected, a signed introspection response included (RFC 9701 §8.1)"
  ) {
    List("token-introspection+jwt", "application/token-introspection+jwt", "dpop+jwt", "logout+jwt")
      .traverse(t => validate(token(), new JOSEObjectType(t)).map(t -> _))
      .map(_.foreach((t, r) => assert(r.isLeft, s"typ $t accepted")))
  }

}
