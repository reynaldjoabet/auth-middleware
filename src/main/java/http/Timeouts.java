package http;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

/**
 * Deadline enforcement for {@code CompletionStage} pipelines, the building block
 * for {@code @RequestTimeout} (ASP.NET Core's {@code [RequestTimeout]}).
 *
 * <p>Uses the JDK's shared delayed executor ({@code orTimeout}); no threads of its
 * own. The fallback is evaluated lazily, only when the deadline is actually hit.
 */
public final class Timeouts {

  private Timeouts() {}

  /**
   * Returns a stage that completes with {@code stage}'s outcome, or with
   * {@code onTimeout.get()} if the deadline elapses first. Failures other than the
   * deadline propagate unchanged.
   *
   * <p>The underlying work is not interrupted — like ASP.NET Core's request
   * timeouts, this bounds the response, and downstream code should observe its own
   * cancellation signals.
   */
  public static <T> CompletionStage<T> within(
      CompletionStage<T> stage, Duration timeout, Supplier<? extends T> onTimeout) {
    CompletableFuture<T> bounded =
        stage.toCompletableFuture().copy().orTimeout(timeout.toNanos(), TimeUnit.NANOSECONDS);
    return bounded.exceptionally(
        error -> {
          Throwable cause =
              error instanceof CompletionException && error.getCause() != null
                  ? error.getCause()
                  : error;
          if (cause instanceof TimeoutException) {
            return onTimeout.get();
          }
          throw error instanceof CompletionException ce ? ce : new CompletionException(error);
        });
  }
}
