package app.http

import cats.effect.{Deferred, IO, Ref}
import cats.effect.std.CountDownLatch
import cats.syntax.all.*

import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.implicits.*
import org.typelevel.ci.*

class LoadSheddingSpec extends CatsEffectSuite {

  /**
    * Holds every request until `release` completes, so in-flight requests stay in flight. Each one
    * counts `entered` down once it is running — i.e. once it holds its permit — so a test can wait
    * for that instead of hoping the scheduler got there.
    */
  private def stalled(entered: CountDownLatch[IO], release: Deferred[IO, Unit]): HttpApp[IO] =
    HttpApp[IO](_ => entered.release *> release.get.as(Response[IO](Status.Ok)))

  private val me     = Request[IO](Method.GET, uri"/me")
  private val health = Request[IO](Method.GET, uri"/health")

  test("requests beyond max-in-flight are shed with 503 + Retry-After, the rest succeed") {
    for {
      entered <- CountDownLatch[IO](2)
      release <- Deferred[IO, Unit]
      shed    <- Ref.of[IO, Int](0)
      app     <- LoadShedding.httpApp[IO](2, Set("/health"), shed.update(_ + 1))(
               stalled(entered, release)
             )
      held   <- List.fill(2)(app.run(me).start).sequence
      _      <- entered.await // both permits are now taken
      extra  <- app.run(me)
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

  test("probe paths are never shed, even with every permit taken") {
    for {
      entered <- CountDownLatch[IO](1)
      release <- Deferred[IO, Unit]
      app     <- LoadShedding.httpApp[IO](1, Set("/health"), IO.unit)(
               HttpApp[IO] { req =>
                 if (req.uri.path.renderString == "/health") IO.pure(Response[IO](Status.Ok))
                 else stalled(entered, release)(req)
               }
             )
      held    <- app.run(me).start
      _       <- entered.await // the only permit is now taken
      control <- app.run(me)
      probe   <- app.run(health)
      _       <- release.complete(())
      _       <- held.joinWithNever
    } yield {
      // The control proves the permit really was held, so the probe passing
      // shows it is exempt rather than that the node happened to be idle.
      assertEquals(control.status, Status.ServiceUnavailable)
      assertEquals(probe.status, Status.Ok)
    }
  }

  test("a permit is returned when the handler fails") {
    for {
      calls <- Ref.of[IO, Int](0)
      app   <- LoadShedding.httpApp[IO](1, Set.empty, IO.unit)(
               HttpApp[IO](_ => calls.update(_ + 1) *> IO.raiseError(new RuntimeException("boom")))
             )
      _ <- app.run(me).attempt
      _ <- app.run(me).attempt
      n <- calls.get
    } yield assertEquals(n, 2)
  }

}
