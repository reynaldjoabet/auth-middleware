package auth

import cats.effect.Sync
import cats.syntax.all.*
import org.slf4j.MDC
import org.typelevel.otel4s.trace.Tracer

/** Attaches the current span's ids to a log record through the SLF4J MDC, so
  * `logback.xml`'s `traceId` / `spanId` fields resolve and a log line can be
  * pivoted to the trace it belongs to.
  *
  * ==Why the awkward shape==
  *
  * The MDC is a thread-local, while a cats-effect fiber may resume on any
  * thread — so the usual "set the MDC for the whole request" trick silently
  * loses the values at the first async boundary, and worse, can leak them onto
  * an unrelated fiber that inherits the thread. The only placement that is
  * always correct is the one used here: read the span context effectfully, then
  * populate, log and clear inside a *single* `delay`, which the runtime cannot
  * split across threads.
  *
  * Hence `logging` is a by-name block containing the SLF4J call itself, not a
  * wrapper around arbitrary effects.
  */
object TraceLogging {

  private val TraceIdField = "trace_id"
  private val SpanIdField = "span_id"

  /** Runs `logging` with `fields` plus the current `trace_id`/`span_id` in the
    * MDC, restoring the previous state afterwards. With no recording span (no
    * exporter configured, or a sampled-out request) only `fields` are set.
    */
  def withTraceContext[F[_]: Sync: Tracer](
      fields: (String, String)*
  )(logging: => Unit): F[Unit] =
    Tracer[F].currentSpanContext.flatMap { spanContext =>
      val traceFields =
        spanContext.filter(_.isValid).toList.flatMap { context =>
          List(
            TraceIdField -> context.traceIdHex,
            SpanIdField -> context.spanIdHex
          )
        }
      Sync[F].delay(inMdc(fields.toList ++ traceFields)(logging))
    }

  private def inMdc(fields: List[(String, String)])(logging: => Unit): Unit = {
    // Restore rather than clear: this thread may already be carrying context
    // put there by whoever called us.
    val previous = fields.map { case (key, _) => key -> Option(MDC.get(key)) }
    fields.foreach { case (key, value) => MDC.put(key, value) }
    try logging
    finally
      previous.foreach {
        case (key, Some(value)) => MDC.put(key, value)
        case (key, None)        => MDC.remove(key)
      }
  }
}
