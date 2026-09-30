package auth

import munit.FunSuite

class LogRateLimiterSpec extends FunSuite {

  private final class FakeClock {
    @volatile var nanos: Long = 0L
  }

  test("admits the budget, suppresses the rest, and reports the count next window") {
    val clock   = new FakeClock
    val limiter = new LogRateLimiter(3, () => clock.nanos)

    val first = List.fill(5)(limiter.tryAcquire())
    assertEquals(first, List(Some(0L), Some(0L), Some(0L), None, None))

    clock.nanos = 1_000_000_000L
    assertEquals(limiter.tryAcquire(), Some(2L))
    // The reset window counts the reporting line, and the count is reported once.
    assertEquals(limiter.tryAcquire(), Some(0L))
  }

}
