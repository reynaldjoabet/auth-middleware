package auth

import java.time.temporal.ChronoUnit
import java.time.Instant
import java.util.{Date, UUID}

import scala.concurrent.duration.*

import cats.effect.IO

import auth.accesstoken.AccessTokenValidator
import auth.revocation.{InvalidationStore, TokenInvalidation}
import com.nimbusds.jwt.JWTClaimsSet
import munit.CatsEffectSuite
import org.http4s.{AuthedRoutes, Header, Headers, Method, Request, Response, Status, Uri}
import org.http4s.dsl.io.*
import org.typelevel.ci.CIString

/**
  * The payroll example end to end, through the http4s middleware:
  *
  * {{{
  *   GET /api/payroll/employees    requires  PayrollAdmin (role)  OR  payroll.read (scope)
  * }}}
  *
  * An invalid or revoked token is `401`; a valid one that meets neither requirement is `403`. A
  * role removed from the user reaches tokens already issued through a subject invalidation.
  */
class TokenInvalidationSpec extends CatsEffectSuite {

  import TestTokens.*

  private val PayrollAdmin = Role("PayrollAdmin")
  private val PayrollRead  = ScopeToken("payroll.read")

  private def app(store: InvalidationStore[IO]) =
    AccessTokenAuth
      .middleware[IO](
        AccessTokenValidator.withKeySource[IO](config, keySource, AuthEvents.noop[IO], store),
        AuthEvents.noop[IO]
      )(
        AccessTokenAuth.requireAny[IO](roles = Set(PayrollAdmin), scopes = Set(PayrollRead))(
          AuthedRoutes.of[AuthContext, IO] {
            case GET -> Root / "api" / "payroll" / "employees" as _ =>
              Ok("employees")
          }
        )
      )
      .orNotFound

  /**
    * A store that has caught up, as the Kafka consumer leaves it.
    */
  private val current: IO[InvalidationStore[IO]] =
    InvalidationStore[IO](maxTokenLifetime = 1.hour, maxStaleness = 1.minute)
      .flatTap(store => IO.realTimeInstant.flatMap(store.markFresh))

  private def token(
      sub: String = "u-1",
      roles: List[String] = Nil,
      scope: Option[String] = None,
      issuedAt: Instant = Instant.now(),
      jti: String = UUID.randomUUID().toString
  ): String = {
    val builder = new JWTClaimsSet.Builder(claims(sub = sub, scope = scope, jti = Some(jti)))
      .issueTime(Date.from(issuedAt))
    if (roles.nonEmpty) { val _ = builder.claim("roles", java.util.List.of(roles*)) }
    sign(builder.build())
  }

  private def get(store: InvalidationStore[IO], bearer: String): IO[Response[IO]] =
    app(store).run(
      Request[IO](Method.GET, Uri.unsafeFromString("/api/payroll/employees"))
        .withHeaders(Headers(Header.Raw(CIString("Authorization"), s"Bearer $bearer")))
    )

  private def challenge(response: Response[IO]): String =
    response.headers.get(CIString("WWW-Authenticate")).fold("")(_.head.value)

  // --- 401 vs 403 -----------------------------------------------------------

  test("the role alone is enough") {
    current
      .flatMap(get(_, token(roles = List("PayrollAdmin"))))
      .map(r => assertEquals(r.status, Status.Ok))
  }

  test("the scope alone is enough") {
    current
      .flatMap(get(_, token(scope = Some("payroll.read"))))
      .map(r => assertEquals(r.status, Status.Ok))
  }

  test("a valid token with neither is 403 insufficient_scope, naming the scope but not the role") {
    current.flatMap(get(_, token(roles = List("Manager"), scope = Some("accounts:read")))).map {
      r =>
        assertEquals(r.status, Status.Forbidden)
        assert(challenge(r).contains("""error="insufficient_scope""""), challenge(r))
        assert(challenge(r).contains("""scope="payroll.read""""), challenge(r))
        assert(!challenge(r).contains("PayrollAdmin"), "role names are internal")
    }
  }

  test("an invalid token is 401, never 403, whatever it claims") {
    val forged = sign(claims(scope = Some("payroll.read")), key = rogueKey)
    current.flatMap(get(_, forged)).map { r =>
      assertEquals(r.status, Status.Unauthorized)
      assert(challenge(r).contains("invalid_token"), challenge(r))
    }
  }

  test("a policy with no role and no scope is refused when the route is built") {
    intercept[IllegalArgumentException](
      AccessTokenAuth.requireAny[IO]()(AuthedRoutes.empty[AuthContext, IO])
    )
  }

  // --- invalidation ---------------------------------------------------------

  test("TokenInvalidated(jti) turns that token into a 401, and only that token") {
    val (revoked, other) = (UUID.randomUUID().toString, UUID.randomUUID().toString)
    for {
      store  <- current
      _      <- store.apply(TokenInvalidation.Token(revoked, Instant.now().plusSeconds(300)))
      first  <- get(store, token(roles = List("PayrollAdmin"), jti = revoked))
      second <- get(store, token(roles = List("PayrollAdmin"), jti = other))
    } yield {
      assertEquals(first.status, Status.Unauthorized)
      assert(challenge(first).contains("invalid_token"), challenge(first))
      assertEquals(second.status, Status.Ok)
    }
  }

  test("role removed: the old token is 401, then a new token without the role is 403") {
    // 10:00 token with Manager/PayrollAdmin; 10:05 role removed; 10:06 old token presented.
    val issued  = Instant.now().minusSeconds(360).truncatedTo(ChronoUnit.SECONDS)
    val removed = issued.plusSeconds(300)
    for {
      store  <- current
      before <- get(store, token(sub = "u-7", roles = List("PayrollAdmin"), issuedAt = issued))
      _      <- store.apply(TokenInvalidation.Subject("u-7", removed, Some("roles-changed")))
      after  <- get(store, token(sub = "u-7", roles = List("PayrollAdmin"), issuedAt = issued))
      // The user signs in again; the new token no longer carries the role.
      renewed <- get(store, token(sub = "u-7", issuedAt = removed.plusSeconds(1)))
      // Another user's token is untouched.
      bystander <- get(store, token(sub = "u-8", roles = List("PayrollAdmin"), issuedAt = issued))
    } yield {
      assertEquals(before.status, Status.Ok)
      assertEquals(after.status, Status.Unauthorized)
      assert(challenge(after).contains("invalid_token"), challenge(after))
      assertEquals(renewed.status, Status.Forbidden)
      assertEquals(bystander.status, Status.Ok)
    }
  }

  test("a store that has not caught up answers 503, not a guess") {
    InvalidationStore[IO](1.hour, 1.minute).flatMap { store =>
      get(store, token(roles = List("PayrollAdmin"))).map(r =>
        assertEquals(r.status, Status.ServiceUnavailable)
      )
    }
  }

}
