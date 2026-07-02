package http

import java.time.Duration
import java.util.concurrent.{CompletableFuture, ExecutionException, TimeUnit}
import java.util.concurrent.atomic.AtomicBoolean

import munit.FunSuite

class TimeoutsSpec extends FunSuite {

  private def await[A](stage: java.util.concurrent.CompletionStage[A]): A =
    stage.toCompletableFuture.get(5, TimeUnit.SECONDS)

  test("a stage that beats the deadline keeps its value") {
    val result = Timeouts.within(
      CompletableFuture.completedFuture("ok"),
      Duration.ofMillis(1),
      () => "fallback"
    )
    assertEquals(await(result), "ok")
  }

  test("a stage that misses the deadline completes with the fallback") {
    val never = new CompletableFuture[String]()
    val result = Timeouts.within(never, Duration.ofMillis(50), () => "fallback")
    assertEquals(await(result), "fallback")
  }

  test("failures other than the deadline propagate unchanged") {
    val failed = CompletableFuture.failedFuture[String](new RuntimeException("boom"))
    val result = Timeouts.within(failed, Duration.ofSeconds(5), () => "fallback")
    val error = intercept[ExecutionException](await(result))
    assertEquals(error.getCause.getMessage, "boom")
  }

  test("the fallback is not evaluated when the stage completes in time") {
    val evaluated = new AtomicBoolean(false)
    val result = Timeouts.within(
      CompletableFuture.completedFuture(42),
      Duration.ofSeconds(5),
      () => { evaluated.set(true); -1 }
    )
    assertEquals(await(result), 42)
    assertEquals(evaluated.get(), false)
  }
}
