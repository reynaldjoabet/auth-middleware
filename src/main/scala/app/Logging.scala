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
  * each entrypoint. The root level comes from the `LOG_LEVEL` environment variable (default
  * `info`), so changing it takes a restart, not a rebuild.
  *
  * Writes go through [[AsyncLogWriter]] — the equivalent of logback's `AsyncAppender` with
  * `neverBlock=true` — so a burst of logging never stalls request threads on stdout.
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
    * `LOG_LEVEL` (trace, debug, info, warn, error; any case), defaulting to info. An unrecognised
    * value is reported on stderr — nothing can log yet — rather than silently ignored.
    */
  private def levelFromEnv: Level =
    sys.env.get("LOG_LEVEL").filter(_.trim.nonEmpty) match {
      case None       => Level.Info
      case Some(name) =>
        Level.get(name.trim).getOrElse {
          System.err.println(s"LOG_LEVEL=$name is not a log level; using info")
          Level.Info
        }
    }

  /**
    * Installs the root handler. Call once, before anything else runs.
    */
  def configure(minimumLevel: Level = levelFromEnv): Unit = {
    val writer = new AsyncLogWriter(ConsoleWriter)
    // Flush what is still queued on exit (SIGTERM included): the last lines
    // before a shutdown are usually the ones someone needs.
    Runtime.getRuntime.addShutdownHook(
      Thread.ofPlatform().unstarted(() => writer.dispose())
    )
    val _ = scribe.Logger.root
      .clearHandlers()
      .withHandler(
        formatter = consoleFormat,
        writer = writer,
        minimumLevel = Some(minimumLevel)
      )
      .replace()
    // http4s logs every connection teardown at INFO; the old logback config
    // pinned it to WARN and this keeps that.
    val _ = scribe.Logger("org.http4s").withMinimumLevel(Level.Warn).replace()
  }

}
