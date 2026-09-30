package app.http

import cats.effect.{Deferred, IO, Ref}
import cats.syntax.all.*

import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.implicits.*
import org.typelevel.ci.*

class LoadSheddingSpec extends CatsEffectSuite {

  /**
    * Holds every request until `release` completes, so in-flight requests stay in flight.
    */
  private def stalled(release: Deferred[IO, Unit]): HttpApp[IO] =
    HttpApp[IO](_ => release.get.as(Response[IO](Status.Ok)))

  test("requests beyond max-in-flight are shed with 503 + Retry-After, the rest succeed") {
    for {
      release <- Deferred[IO, Unit]
      shed    <- Ref.of[IO, Int](0)
      app     <- LoadShedding.httpApp[IO](2, Set("/health"), shed.update(_ + 1))(stalled(release))
      held    <- List.fill(2)(app.run(Request[IO](Method.GET, uri"/me")).start).sequence
      // Let the two held requests take their permits.
      _      <- IO.cede.replicateA_(10)
      extra  <- app.run(Request[IO](Method.GET, uri"/me"))
      _      <- release.complete(())
      served <- held.traverse(_.joinWithNever)
      count  <- shed.get
    } yield {
      assertEquals(extra.status, Status.ServiceUnavailable)
      assertEquals(extra.headers.get(ci"Retry-After").map(_.head.value), Some("1"))
      assertEquals(served.map(_.status), List(Status.Ok, Status.Ok))
      assertEquals(count, 1)
    }
  }

  test("probe paths are never shed") {
    for {
      release <- Deferred[IO, Unit]
      app     <- LoadShedding.httpApp[IO](1, Set("/health"), IO.unit)(
               HttpApp[IO] { req =>
                 if (req.uri.path.renderString == "/health") IO.pure(Response[IO](Status.Ok))
                 else release.get.as(Response[IO](Status.Ok))
               }
             )
      held   <- app.run(Request[IO](Method.GET, uri"/me")).start
      _      <- IO.cede.replicateA_(10)
      health <- app.run(Request[IO](Method.GET, uri"/health"))
      _      <- release.complete(())
      _      <- held.joinWithNever
    } yield assertEquals(health.status, Status.Ok)
  }

  test("a permit is returned when the handler fails") {
    for {
      calls <- Ref.of[IO, Int](0)
      app   <- LoadShedding.httpApp[IO](1, Set.empty, IO.unit)(
               HttpApp[IO](_ => calls.update(_ + 1) *> IO.raiseError(new RuntimeException("boom")))
             )
      _ <- app.run(Request[IO](Method.GET, uri"/me")).attempt
      _ <- app.run(Request[IO](Method.GET, uri"/me")).attempt
      n <- calls.get
    } yield assertEquals(n, 2)
  }

}
