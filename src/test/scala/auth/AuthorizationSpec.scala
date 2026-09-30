package auth

import java.util.{Date, UUID}
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}

import scala.concurrent.duration.*

import cats.effect.IO

import auth.accesstoken.AccessTokenValidator
import auth.authorization.{AccessEvaluator, AuthZen}
import auth.revocation.TokenDenylist
import com.nimbusds.jwt.JWTClaimsSet
import io.circe.Json
import munit.CatsEffectSuite
import org.http4s.{AuthedRoutes, Header, Headers, HttpApp, Method, Request, Response, Status, Uri}
import org.http4s.circe.*
import org.http4s.client.Client
import org.http4s.dsl.io.*
import org.http4s.implicits.*
import org.typelevel.ci.CIString

/**
  * The two authorization levels on one payroll API:
  *
  *   - Level 1, from the token alone: role or scope, tenant
  *   - Level 2, asked of the IAM policy decision point (AuthZEN): may this user read this employee?
  */
class AuthorizationSpec extends CatsEffectSuite {

  import TestTokens.*

  // --- a fake AuthZEN PDP ---------------------------------------------------

  private final class FakePdp {

    val calls    = new AtomicInteger(0)
    val lastBody = new AtomicReference[Json](Json.Null)
    // (subject id, action, resource id) the PDP allows.
    val allowed                            = new AtomicReference(Set(("u-1", "can_read", "123")))
    @volatile var failWith: Option[Status] = None
    @volatile var delay: FiniteDuration    = Duration.Zero

    val app: HttpApp[IO] = HttpApp[IO] {
      case req @ POST -> Root / "access" / "v1" / "evaluation" =>
        IO(calls.incrementAndGet()) *> IO.sleep(delay) *> req.as[Json].flatMap { body =>
          IO(lastBody.set(body)) *> (failWith match {
            case Some(status) => IO.pure(Response[IO](status))
            case None         =>
              val c        = body.hcursor
              val decision = (
                c.downField("subject").get[String]("id"),
                c.downField("action").get[String]("name"),
                c.downField("resource").get[String]("id")
              ) match {
                case (Right(s), Right(a), Right(r)) => allowed.get.contains((s, a, r))
                case _                              => false
              }
              Ok(Json.obj("decision" -> Json.fromBoolean(decision)))
          })
        }
      case _ => IO.pure(Response[IO](Status.NotFound))
    }

  }

  private def evaluator(pdp: FakePdp, cacheTtl: FiniteDuration = Duration.Zero) =
    AccessEvaluator.authZen[IO](
      AccessEvaluator.PdpConfig(
        endpoint = uri"https://iam.test.example",
        requestTimeout = 200.millis,
        cacheTtl = cacheTtl
      ),
      Client.fromHttpApp(pdp.app)
    )

  // --- the API --------------------------------------------------------------

  private val PayrollAdmin = Role("PayrollAdmin")
  private val PayrollRead  = ScopeToken("payroll.read")

  /**
    * {{{
    *   GET /tenants/{tenant}/payroll/employees/{id}
    *     Level 1: tenant matches, and PayrollAdmin or payroll.read
    *     Level 2: PDP allows can_read on employee {id}
    * }}}
    */
  private def app(pdp: AccessEvaluator[IO]) = {
    val employee = AuthedRoutes.of[AuthContext, IO] {
      case GET -> Root / "tenants" / _ / "payroll" / "employees" / id as _ => Ok(s"employee $id")
    }
    val tenantOf: org.http4s.AuthedRequest[IO, AuthContext] => Option[String] =
      _.req.pathInfo.segments.toList.map(_.decoded()) match {
        case "tenants" :: tenant :: _ => Some(tenant)
        case _                        => None
      }
    val employeeOf: org.http4s.AuthedRequest[IO, AuthContext] => AuthZen.Resource =
      req => AuthZen.Resource("employee", req.req.pathInfo.segments.last.decoded())

    AccessTokenAuth
      .middleware[IO](
        AccessTokenValidator
          .withKeySource[IO](config, keySource, AuthEvents.noop[IO], TokenDenylist.none[IO]),
        AuthEvents.noop[IO]
      )(
        AccessTokenAuth.requireTenant[IO](tenantOf)(
          AccessTokenAuth.requireAny[IO](roles = Set(PayrollAdmin), scopes = Set(PayrollRead))(
            AccessTokenAuth.requirePermission[IO](pdp, "can_read", employeeOf)(employee)
          )
        )
      )
      .orNotFound
  }

  private def token(
      sub: String = "u-1",
      tenant: Option[String] = Some("customer-123"),
      roles: List[String] = List("PayrollAdmin"),
      scp: List[String] = Nil
  ): String = {
    val builder = new JWTClaimsSet.Builder(
      claims(sub = sub, scope = None, jti = Some(UUID.randomUUID().toString))
    )
      .issueTime(new Date())
    tenant.foreach { t =>
      val _ = builder.claim("tenant", t)
    }
    if (roles.nonEmpty) { val _ = builder.claim("roles", java.util.List.of(roles*)) }
    if (scp.nonEmpty) { val _ = builder.claim("scp", java.util.List.of(scp*)) }
    sign(builder.build())
  }

  private def get(app: HttpApp[IO], path: String, bearer: String): IO[Response[IO]] =
    app.run(
      Request[IO](Method.GET, Uri.unsafeFromString(path))
        .withHeaders(Headers(Header.Raw(CIString("Authorization"), s"Bearer $bearer")))
    )

  private val employee123 = "/tenants/customer-123/payroll/employees/123"

  // --- Level 1: tenant ------------------------------------------------------

  test("a token for another tenant is 403 access_denied, before the PDP is asked") {
    val pdp = new FakePdp
    for {
      e    <- evaluator(pdp)
      r    <- get(app(e), "/tenants/customer-999/payroll/employees/123", token())
      body <- r.as[Json]
    } yield {
      assertEquals(r.status, Status.Forbidden)
      assertEquals(body.hcursor.get[String]("error"), Right("access_denied"))
      assert(r.headers.get(CIString("WWW-Authenticate")).isEmpty, "nothing a client could request")
      assertEquals(pdp.calls.get, 0)
    }
  }

  test("a token without a tenant claim is refused on a tenant-scoped route") {
    val pdp = new FakePdp
    evaluator(pdp)
      .flatMap(e => get(app(e), employee123, token(tenant = None)))
      .map(r => assertEquals(r.status, Status.Forbidden))
  }

  test("scopes as an scp array count, like a scope string") {
    val pdp = new FakePdp
    evaluator(pdp)
      .flatMap(e => get(app(e), employee123, token(roles = Nil, scp = List("payroll.read"))))
      .map(r => assertEquals(r.status, Status.Ok))
  }

  // --- Level 2: the PDP -----------------------------------------------------

  test("the PDP allows: 200, after an AuthZEN request naming user, tenant, action and resource") {
    val pdp = new FakePdp
    for {
      e <- evaluator(pdp)
      r <- get(app(e), employee123, token())
    } yield {
      assertEquals(r.status, Status.Ok)
      val c = pdp.lastBody.get.hcursor
      assertEquals(c.downField("subject").get[String]("type"), Right("user"))
      assertEquals(c.downField("subject").get[String]("id"), Right("u-1"))
      assertEquals(
        c.downField("subject").downField("properties").get[String]("tenant"),
        Right("customer-123")
      )
      assertEquals(c.downField("action").get[String]("name"), Right("can_read"))
      assertEquals(c.downField("resource").get[String]("type"), Right("employee"))
      assertEquals(c.downField("resource").get[String]("id"), Right("123"))
      assert(
        c.downField("subject").downField("properties").downField("roles").failed,
        "the PDP decides from its own current roles, not the token's"
      )
    }
  }

  test("the PDP denies: 403 access_denied, although the token's role would allow it") {
    val pdp = new FakePdp
    evaluator(pdp)
      .flatMap(e => get(app(e), "/tenants/customer-123/payroll/employees/456", token()))
      .map(r => assertEquals(r.status, Status.Forbidden))
  }

  test("a role removed in IAM takes effect on the next call, with no new token") {
    val pdp = new FakePdp
    for {
      e      <- evaluator(pdp)
      before <- get(app(e), employee123, token())
      _      <- IO(pdp.allowed.set(Set.empty))
      after  <- get(app(e), employee123, token())
    } yield {
      assertEquals(before.status, Status.Ok)
      assertEquals(after.status, Status.Forbidden)
    }
  }

  test("a PDP error or a slow PDP is 503, never an answer") {
    val (broken, slow) = (new FakePdp, new FakePdp)
    broken.failWith = Some(Status.InternalServerError)
    slow.delay = 1.second
    for {
      b <- evaluator(broken).flatMap(e => get(app(e), employee123, token()))
      s <- evaluator(slow).flatMap(e => get(app(e), employee123, token()))
    } yield {
      assertEquals(b.status, Status.ServiceUnavailable)
      assertEquals(s.status, Status.ServiceUnavailable)
    }
  }

  test("decisions are reused for the cache TTL; a different resource asks again") {
    val pdp = new FakePdp
    for {
      e <- evaluator(pdp, cacheTtl = 1.minute)
      _ <- get(app(e), employee123, token())
      _ <- get(app(e), employee123, token())
      _ <- get(app(e), "/tenants/customer-123/payroll/employees/456", token())
    } yield assertEquals(pdp.calls.get, 2)
  }

  test("errors are not cached") {
    val pdp = new FakePdp
    pdp.failWith = Some(Status.BadGateway)
    for {
      e      <- evaluator(pdp, cacheTtl = 1.minute)
      failed <- get(app(e), employee123, token())
      _      <- IO { pdp.failWith = None }
      ok     <- get(app(e), employee123, token())
    } yield {
      assertEquals(failed.status, Status.ServiceUnavailable)
      assertEquals(ok.status, Status.Ok)
    }
  }

  test("a machine token is sent as a client subject") {
    val pdp = new FakePdp
    // client_credentials: sub equals client_id, so no user is present.
    val machine = sign(
      new JWTClaimsSet.Builder(claims(sub = "mobile-app", scope = Some("payroll.read")))
        .claim("tenant", "customer-123")
        .build()
    )
    for {
      e <- evaluator(pdp)
      _ <- get(app(e), employee123, machine)
    } yield {
      val subject = pdp.lastBody.get.hcursor.downField("subject")
      assertEquals(subject.get[String]("type"), Right("client"))
      assertEquals(subject.get[String]("id"), Right("mobile-app"))
    }
  }

  test("the PDP endpoint must be https") {
    intercept[IllegalArgumentException](
      AccessEvaluator.PdpConfig(endpoint = uri"http://iam.test.example")
    )
  }

}
