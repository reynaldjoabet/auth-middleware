package auth
package revocation

import java.time.Instant

import scala.concurrent.duration.*

import cats.effect.IO

import munit.CatsEffectSuite

class InvalidationStoreSpec extends CatsEffectSuite {

  private def fresh(maxStaleness: FiniteDuration = 1.minute, margin: FiniteDuration = 5.minutes) =
    InvalidationStore[IO](1.hour, maxStaleness, margin).flatTap(_.markFresh(Instant.now()))

  private def cutoff(store: InvalidationStore[IO], subject: String): IO[Option[Instant]] =
    store.subjects.get.revokedBefore(subject)

  test("before the first catch-up it answers nothing and is not ready") {
    InvalidationStore[IO](1.hour, 1.minute).flatMap { store =>
      for {
        ready  <- store.ready
        answer <- store.isRevoked("x").attempt
      } yield {
        assert(!ready)
        assert(answer.left.exists(_.isInstanceOf[InvalidationStore.NotCurrent]), answer.toString)
      }
    }
  }

  test("past max-staleness it fails closed again") {
    for {
      store  <- InvalidationStore[IO](1.hour, maxStaleness = 100.millis)
      _      <- store.markFresh(Instant.now().minusSeconds(1))
      ready  <- store.ready
      answer <- store.isRevoked("x").attempt
    } yield {
      assert(!ready)
      assert(answer.isLeft)
    }
  }

  test("marking fresh never moves backwards") {
    for {
      store <- InvalidationStore[IO](1.hour, maxStaleness = 1.second)
      _     <- store.markFresh(Instant.now())
      _     <- store.markFresh(Instant.now().minusSeconds(60))
      ready <- store.ready
    } yield assert(ready)
  }

  test("a revoked jti is revoked; others are not") {
    for {
      store <- fresh()
      _     <- store.apply(TokenInvalidation.Token("a", Instant.now().plusSeconds(60)))
      a     <- store.isRevoked("a")
      b     <- store.isRevoked("b")
    } yield {
      assert(a)
      assert(!b)
    }
  }

  test("the latest subject cut-off wins, in whatever order they arrive") {
    val (early, late) =
      (Instant.parse("2026-10-01T09:00:00Z"), Instant.parse("2026-10-01T10:00:00Z"))
    for {
      store <- fresh()
      _     <- store.apply(TokenInvalidation.Subject("u", late, None))
      _     <- store.apply(TokenInvalidation.Subject("u", early, None))
      _     <- store.apply(TokenInvalidation.Subject("u", late, None))
      found <- cutoff(store, "u")
      none  <- cutoff(store, "v")
    } yield {
      assertEquals(found, Some(late))
      assertEquals(none, None)
    }
  }

  test("entries go once their tokens have expired") {
    for {
      store  <- fresh(margin = Duration.Zero)
      _      <- store.apply(TokenInvalidation.Token("t", Instant.now().plusMillis(50)))
      before <- store.isRevoked("t")
      _      <- IO.sleep(150.millis)
      after  <- store.isRevoked("t")
    } yield {
      assert(before)
      assert(!after)
    }
  }

  test("a token issued in the cut-off's second counts as revoked; the next second does not") {
    val before = Instant.parse("2026-10-01T10:05:00.600Z")
    assert(SubjectRevocations.covers(before, Some(Instant.parse("2026-10-01T10:04:59Z"))))
    assert(SubjectRevocations.covers(before, Some(Instant.parse("2026-10-01T10:05:00Z"))))
    assert(!SubjectRevocations.covers(before, Some(Instant.parse("2026-10-01T10:05:01Z"))))
    assert(SubjectRevocations.covers(before, None), "no iat: its age cannot be shown")
  }

}
