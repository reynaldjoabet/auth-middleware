package auth

import cats.effect.IO
import munit.CatsEffectSuite

class AuditSpec extends CatsEffectSuite {
  import TestTokens.*

  private val validator =
    JwtValidator.fromKeySource[IO](
      config,
      keySource,
      AuthEvents.noop[IO],
      TokenDenylist.none[IO]
    )

  test("AuditAuthEvents records granted (with subject) and denied decisions") {
    for {
      pair <- Audit.inMemory[IO]
      (sink, read) = pair
      events = AuditAuthEvents[IO](sink, AuthEvents.noop[IO])
      ctx <- validator
        .validate(sign(claims()))
        .map(_.fold(e => fail(s"setup: $e"), identity))
      _ <- events.authSucceeded(ctx)
      _ <- events.authFailed(AuthError.InvalidToken.Rejected, "detail")
      records <- read
    } yield {
      assertEquals(records.length, 2)
      assertEquals(records(0).decision, "granted")
      assertEquals(records(0).subject, Some("user-123"))
      assertEquals(records(0).clientId, Some("mobile-app"))
      assertEquals(records(1).decision, "denied:invalid_token")
      assertEquals(records(1).subject, None)
    }
  }
}
