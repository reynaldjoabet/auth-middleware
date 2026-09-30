package auth
package revocation

import scala.concurrent.duration.*

import cats.effect.{IO, Ref}
import cats.syntax.all.*

import io.circe.Json
import munit.CatsEffectSuite
import org.http4s.{HttpApp, Response, Status}
import org.http4s.circe.*
import org.http4s.client.Client
import org.http4s.implicits.*

/**
  * Concurrent cache misses for one token must cost one round trip to the AS, not one per caller.
  */
class IntrospectionCoalescingSpec extends CatsEffectSuite {

  import TokenIntrospection.{IntrospectionConfig, Result}

  private val cfg = IntrospectionConfig(
    endpoint = uri"https://as.test.example/introspect",
    clientId = "rs-client",
    clientSecret = "s3cret"
  )

  private def slowAs(calls: Ref[IO, Int], answer: IO[Response[IO]]): Client[IO] =
    Client.fromHttpApp(HttpApp[IO](_ => calls.update(_ + 1) *> IO.sleep(100.millis) *> answer))

  private val active: IO[Response[IO]] =
    IO.pure(Response[IO](Status.Ok).withEntity(Json.obj("active" -> Json.True)))

  test("concurrent misses for one token share a single introspection call") {
    for {
      calls         <- Ref.of[IO, Int](0)
      introspection <- TokenIntrospection.http4s[IO](cfg, slowAs(calls, active))
      results       <- List.fill(50)("the-token").parTraverse(introspection.check)
      n             <- calls.get
    } yield {
      assert(results.forall(_ == Result.Active), results)
      assertEquals(n, 1)
    }
  }

  test("distinct tokens are not coalesced") {
    for {
      calls         <- Ref.of[IO, Int](0)
      introspection <- TokenIntrospection.http4s[IO](cfg, slowAs(calls, active))
      _             <- List("a", "b", "c").parTraverse(introspection.check)
      n             <- calls.get
    } yield assertEquals(n, 3)
  }

  test("an Unavailable answer is shared by the waiters but not remembered") {
    val down = IO.pure(Response[IO](Status.BadGateway))
    for {
      calls         <- Ref.of[IO, Int](0)
      introspection <- TokenIntrospection.http4s[IO](cfg, slowAs(calls, down))
      burst         <- List.fill(10)("t").parTraverse(introspection.check)
      _             <- introspection.check("t")
      n             <- calls.get
    } yield {
      assert(burst.forall(_ == Result.Unavailable), burst)
      assertEquals(n, 2)
    }
  }

}
