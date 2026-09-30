package auth

import java.util.concurrent.atomic.AtomicLong

/**
  * Admits at most `perSecond` log lines per one-second window and counts the rest.
  *
  * Authentication rejections are attacker-driven: whoever sends a million junk tokens a second
  * decides how much this service logs. Unbounded, that makes the log pipeline the cheapest way to
  * degrade the node (and to bury the lines that matter). Metrics still count every decision
  * (`auth.decisions`); this bounds only the text.
  *
  * Lock-free and approximate at window edges: a burst straddling a boundary may admit slightly more
  * than `perSecond`, which is fine for a log budget.
  */
final class LogRateLimiter(perSecond: Int, nanoTime: () => Long = () => System.nanoTime()) {

  require(perSecond > 0, "perSecond must be positive")

  private val windowStart = new AtomicLong(nanoTime())
  private val admitted    = new AtomicLong(0L)
  private val suppressed  = new AtomicLong(0L)

  /**
    * @return
    *   `Some(n)` if this line may be logged, where `n` lines were suppressed in the previous window
    *   (report them alongside), or `None` if this line is over budget.
    */
  def tryAcquire(): Option[Long] = {
    val now   = nanoTime()
    val start = windowStart.get()
    if (now - start >= 1_000_000_000L && windowStart.compareAndSet(start, now)) {
      admitted.set(1L)
      Some(suppressed.getAndSet(0L))
    } else if (admitted.incrementAndGet() <= perSecond) Some(0L)
    else {
      suppressed.incrementAndGet()
      None
    }
  }

}
