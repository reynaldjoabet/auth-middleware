package auth

import scribe.{Level, LogRecord}
import scribe.format.*
import scribe.handler.{AsynchronousLogHandle, Overflow}
import scribe.output.{EmptyOutput, LogOutput, TextOutput}
import scribe.throwable.TraceLoggableMessage
import scribe.writer.ConsoleWriter
import zio.{Cause, FiberId, FiberRefs, LogLevel, LogSpan, Runtime, Trace, ZLayer, ZLogger}

/**
  * Logging for the ZIO service, on scribe directly.
  *
  * Three sources end up in one console handler:
  *   - `ZIO.log*` calls, through [[zioLogger]], which replaces ZIO's default loggers
  *   - scribe calls (e.g. [[AuthEvents]])
  *   - Netty and the Redis client, which log through SLF4J; `scribe-slf4j2` is the SLF4J provider
  *
  * Configured in code rather than a logging file: [[configure]] installs the root handler with the
  * level from `app.log-level` (`LOG_LEVEL`). Lines are written from a background thread, dropping
  * the oldest when the buffer fills, so a burst of logging never stalls a request on stdout.
  */
object Logging {

  /**
    * ZIO log annotations and spans as ` [key=value …]`, sorted by key; nothing when there are none,
    * so a line without context carries no empty brackets.
    */
  private object mdcBlock extends FormatBlock {

    override def format(record: LogRecord): LogOutput =
      if (record.data.isEmpty) EmptyOutput
      else
        new TextOutput(
          record.data.toList
            .sortBy(_._1)
            .map((key, value) => s"$key=${value()}")
            .mkString(" [", " ", "]")
        )

  }

  private val consoleFormat: Formatter =
    formatter"$dateFull $levelPaddedRight [$threadName] $loggerName$mdcBlock - $messages"

  private val handle = AsynchronousLogHandle(overflow = Overflow.DropOld)

  /**
    * Installs the root handler at `minimumLevel`. Call once, before the server starts.
    */
  def configure(minimumLevel: Level): Unit = {
    val _ = scribe.Logger.root
      .clearHandlers()
      .clearModifiers()
      .withHandler(
        formatter = consoleFormat,
        writer = ConsoleWriter,
        minimumLevel = Some(minimumLevel),
        handle = handle
      )
      .replace()
    // Flush what is still queued on exit (SIGTERM included): the last lines
    // before a shutdown are usually the ones someone needs.
    java.lang.Runtime.getRuntime.addShutdownHook(
      Thread.ofPlatform().unstarted(() => handle.flush())
    )
  }

  /**
    * Replaces ZIO's default loggers with [[zioLogger]]; the app's `bootstrap`.
    */
  val layer: ZLayer[Any, Nothing, Unit] =
    Runtime.removeDefaultLoggers ++ Runtime.addLogger(zioLogger)

  /**
    * ZIO's log calls as scribe records. The logger is named after the class that called `ZIO.log`
    * (from its `Trace`), so levels can be set per class as for any other scribe logger. Annotations
    * and span durations go to the record's data, which [[mdcBlock]] prints.
    */
  val zioLogger: ZLogger[String, Unit] = new ZLogger[String, Unit] {

    override def apply(
        trace: Trace,
        fiberId: FiberId,
        logLevel: LogLevel,
        message: () => String,
        cause: Cause[Any],
        context: FiberRefs,
        spans: List[LogSpan],
        annotations: Map[String, String]
    ): Unit = {
      val level                     = levelOf(logLevel)
      val (className, method, line) = location(trace)
      val logger                    = scribe.Logger(className)
      if (logger.includes(level)) {
        val now  = java.lang.System.currentTimeMillis()
        val data = annotations.map((k, v) => k -> (() => v)) ++
          spans.map(span => span.label -> (() => s"${now - span.startTime}ms"))
        val record = LogRecord
          .simple(
            message(),
            fileName = className,
            className = className,
            methodName = method,
            line = line,
            level = level,
            data = data
          )
          .withMessages(
            cause.failures.collect { case t: Throwable => t }.map(TraceLoggableMessage(_)) ++
              cause.defects.map(TraceLoggableMessage(_))*
          )
        logger.log(record)
      }
    }

  }

  private def levelOf(level: LogLevel): Level =
    if (level >= LogLevel.Fatal) Level.Fatal
    else if (level >= LogLevel.Error) Level.Error
    else if (level >= LogLevel.Warning) Level.Warn
    else if (level >= LogLevel.Info) Level.Info
    else if (level >= LogLevel.Debug) Level.Debug
    else Level.Trace

  /**
    * `(class, method, line)` from a ZIO trace such as `auth.Main.run(Main.scala:42)`.
    */
  private def location(trace: Trace): (String, Option[String], Option[Int]) =
    trace match {
      case Trace(location, _, line) =>
        val dot = location.lastIndexOf('.')
        if (dot <= 0) (location, None, Some(line))
        else (location.substring(0, dot), Some(location.substring(dot + 1)), Some(line))
      case _ => ("zio", None, None)
    }

}
