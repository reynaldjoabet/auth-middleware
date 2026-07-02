package http

import java.time.Duration
import java.util.concurrent.atomic.AtomicLong

import munit.FunSuite

class TokenBucketRateLimiterSpec extends FunSuite {

  private def limiterWithClock(
      permits: Long,
      window: Duration
  ): (TokenBucketRateLimiter, AtomicLong) = {
    val clock = new AtomicLong(0L)
    (new TokenBucketRateLimiter(permits, window, () => clock.get()), clock)
  }

  test("allows exactly `permits` requests within a window, then rejects") {
    val (limiter, _) = limiterWithClock(5, Duration.ofMinutes(1))
    val granted = (1 to 5).map(_ => limiter.tryAcquire("client-a"))
    assertEquals(granted.forall(identity), true)
    assertEquals(limiter.tryAcquire("client-a"), false)
  }

  test("keys are limited independently") {
    val (limiter, _) = limiterWithClock(1, Duration.ofMinutes(1))
    assertEquals(limiter.tryAcquire("client-a"), true)
    assertEquals(limiter.tryAcquire("client-a"), false)
    assertEquals(limiter.tryAcquire("client-b"), true)
  }

  test("tokens refill continuously as time passes") {
    val (limiter, clock) = limiterWithClock(4, Duration.ofSeconds(60))
    (1 to 4).foreach(_ => assertEquals(limiter.tryAcquire("k"), true))
    assertEquals(limiter.tryAcquire("k"), false)

    // Half a window refills half the bucket: 2 tokens.
    val _ = clock.addAndGet(Duration.ofSeconds(30).toNanos)
    assertEquals(limiter.tryAcquire("k"), true)
    assertEquals(limiter.tryAcquire("k"), true)
    assertEquals(limiter.tryAcquire("k"), false)
  }

  test("refill never exceeds bucket capacity") {
    val (limiter, clock) = limiterWithClock(2, Duration.ofSeconds(1))
    assertEquals(limiter.tryAcquire("k"), true)
    val _ = clock.addAndGet(Duration.ofMinutes(10).toNanos)
    assertEquals(limiter.tryAcquire("k"), true)
    assertEquals(limiter.tryAcquire("k"), true)
    assertEquals(limiter.tryAcquire("k"), false)
  }

  test("retryAfterSeconds is 0 while under the limit and exact when exhausted") {
    // 5 permits per 60s = one token every 12s.
    val (limiter, _) = limiterWithClock(5, Duration.ofSeconds(60))
    assertEquals(limiter.retryAfterSeconds("k"), 0L)
    (1 to 5).foreach(_ => assertEquals(limiter.tryAcquire("k"), true))
    assertEquals(limiter.retryAfterSeconds("k"), 12L)
  }

  test("retryAfterSeconds shrinks as the refill approaches") {
    val (limiter, clock) = limiterWithClock(5, Duration.ofSeconds(60))
    (1 to 5).foreach(_ => assertEquals(limiter.tryAcquire("k"), true))
    val _ = clock.addAndGet(Duration.ofSeconds(9).toNanos)
    assertEquals(limiter.retryAfterSeconds("k"), 3L)
    val _2 = clock.addAndGet(Duration.ofSeconds(3).toNanos)
    assertEquals(limiter.retryAfterSeconds("k"), 0L)
    assertEquals(limiter.tryAcquire("k"), true)
  }

  test("rejects non-positive permits and windows") {
    intercept[IllegalArgumentException] {
      new TokenBucketRateLimiter(0, Duration.ofSeconds(1))
    }
    intercept[IllegalArgumentException] {
      new TokenBucketRateLimiter(1, Duration.ZERO)
    }
  }
}
