package auth

import cats.effect.{IO, Ref}
import munit.CatsEffectSuite
import org.typelevel.otel4s.metrics.Meter

/** The observability sinks: `combine` fan-out (logs + metrics side by side) and
  * the otel adapter (Duende's Telemetry counters), including the
  * challenge-vs-failure separation.
  */
class AuthEventsSpec extends CatsEffectSuite {

  private def recording(
      failed: Ref[IO, Int],
      challenged: Ref[IO, Int]
  ): AuthEvents[IO] =
    new AuthEvents[IO] {
      def authSucceeded(ctx: AuthContext): IO[Unit] = IO.unit
      def authFailed(error: AuthError, internalDetail: String): IO[Unit] =
        failed.update(_ + 1)
      override def challengeIssued(
          error: AuthError,
          internalDetail: String
      ): IO[Unit] =
        challenged.update(_ + 1)
    }

  test(
    "combine fans out to every sink, keeping challenges distinct from failures"
  ) {
    for {
      aFailed <- Ref.of[IO, Int](0)
      aChallenged <- Ref.of[IO, Int](0)
      bFailed <- Ref.of[IO, Int](0)
      bChallenged <- Ref.of[IO, Int](0)
      events = AuthEvents.combine(
        recording(aFailed, aChallenged),
        recording(bFailed, bChallenged)
      )
      _ <- events.authFailed(AuthError.MissingToken, "detail")
      _ <- events.challengeIssued(AuthError.MissingToken, "detail")
      _ <- assertIO(aFailed.get, 1)
      _ <- assertIO(bFailed.get, 1)
      _ <- assertIO(aChallenged.get, 1)
      _ <- assertIO(bChallenged.get, 1)
    } yield ()
  }

  test("otel adapter constructs its counters and records without error") {
    for {
      events <- AuthEvents.otel[IO](Meter.noop[IO])
      _ <- events.authFailed(AuthError.MissingToken, "detail")
      _ <- events.challengeIssued(AuthError.MissingToken, "detail")
    } yield ()
  }
}
