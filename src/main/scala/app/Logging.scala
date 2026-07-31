package app

import scribe.format.*
import scribe.writer.ConsoleWriter
import scribe.Level

/**
  * Console logging configuration — scribe's replacement for `logback.xml`.
  *
  * scribe is the SLF4J provider (`scribe-slf4j2`), so this configures *all* logging, not just
  * scribe calls: the codebase logs through `org.slf4j.LoggerFactory`, and so do http4s, Play,
  * Pekko, HikariCP, Flyway and Nimbus. Nothing in the source had to change for the swap — that is
  * the point of logging to the facade rather than to a backend.
  *
  * The trade-off against the XML it replaces: configuration is now typed and compiled, but it is
  * also code, so it must run before anything logs — hence [[configure]] as the first statement of
  * each entrypoint. Redeploying to change a log level is the cost; the previous setup could not be
  * edited at runtime either, since the XML shipped inside the jar.
  *
  * One deliberate regression: logback's `AsyncAppender` (queue 8192, `neverBlock=true`) is gone,
  * and scribe's console writer is synchronous. If a burst of logging ever shows up in request
  * latency, that is the thing to revisit.
  */
object Logging {

  /**
    * Mirrors the old logback pattern field for field, so existing log-parsing rules keep working.
    * The MDC fields resolve to empty rather than vanishing when no span is in scope, keeping every
    * line the same shape.
    */
  private val consoleFormat: Formatter =
    formatter"$dateFull $levelPaddedRight [$threadName] $loggerName traceId=${mdc("trace_id")} spanId=${mdc("span_id")} requestId=${mdc("request_id")} - $messages$newLine"

  /**
    * Installs the root handler. Call once, before anything else runs.
    */
  def configure(minimumLevel: Level = Level.Info): Unit = {
    val _ = scribe.Logger.root
      .clearHandlers()
      .withHandler(
        formatter = consoleFormat,
        writer = ConsoleWriter,
        minimumLevel = Some(minimumLevel)
      )
      .replace()
    // http4s logs every connection teardown at INFO; the old logback config
    // pinned it to WARN and this keeps that.
    val _ = scribe.Logger("org.http4s").withMinimumLevel(Level.Warn).replace()
  }

}
