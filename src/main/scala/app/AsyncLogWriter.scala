package app

import java.util.concurrent.{ArrayBlockingQueue, TimeUnit}
import java.util.concurrent.atomic.AtomicLong

import scribe.output.format.OutputFormat
import scribe.output.LogOutput
import scribe.writer.Writer
import scribe.LogRecord

/**
  * Moves the actual write (the syscall) off the request thread onto one daemon thread, through a
  * bounded queue that drops rather than blocks when full.
  *
  * The record is formatted on the caller's thread before it gets here, so MDC fields (trace and
  * request ids) are captured where they are valid. When the queue overflows the line is dropped and
  * counted, and the next line written reports the count: under a log storm a request never waits on
  * stdout, and the loss is visible rather than silent.
  *
  * scribe's own `AsynchronousLogHandle` is not used: its drain thread sleeps 1 ms after every
  * record, which caps throughput near 1,000 lines/s.
  */
final class AsyncLogWriter(underlying: Writer, capacity: Int = 65_536) extends Writer {

  private final case class Entry(record: LogRecord, output: LogOutput, format: OutputFormat)

  private val queue   = new ArrayBlockingQueue[Entry](capacity)
  private val dropped = new AtomicLong(0L)

  private val drainer: Thread =
    Thread
      .ofPlatform()
      .daemon(true)
      .name("log-writer")
      .start(() =>
        try while (true) writeOne(queue.take())
        catch { case _: InterruptedException => () }
      )

  override def write(record: LogRecord, output: LogOutput, outputFormat: OutputFormat): Unit =
    if (!queue.offer(Entry(record, output, outputFormat))) {
      val _ = dropped.incrementAndGet()
    }

  /**
    * Stops the drain thread and writes what is still queued, waiting up to a second for an
    * in-progress write. Called from the JVM shutdown hook so the last lines before exit — often the
    * interesting ones — are not lost.
    */
  override def dispose(): Unit = {
    drainer.interrupt()
    drainer.join(1_000L)
    var next = queue.poll(0L, TimeUnit.MILLISECONDS)
    while (next != null) {
      writeOne(next)
      next = queue.poll(0L, TimeUnit.MILLISECONDS)
    }
  }

  private def writeOne(entry: Entry): Unit = {
    val lost = dropped.getAndSet(0L)
    if (lost > 0L)
      System.err.println(s"log-writer: queue full, dropped $lost log line(s)")
    underlying.write(entry.record, entry.output, entry.format)
  }

}
