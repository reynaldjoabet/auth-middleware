package app.http

import java.util.concurrent.ThreadLocalRandom
import java.util.UUID

/**
  * The correlation-id rules both services apply to `X-Request-ID`: reuse a safe inbound value,
  * otherwise mint one. Framework-independent; each service's middleware applies them.
  *
  * ==Why an inbound id is not trusted verbatim==
  *
  * The header is attacker-controlled and its value is written to logs. A caller could inject
  * newlines (forging log records), or megabytes of text, into every line correlated with the
  * request. An id that is not a short, boring token is therefore discarded and replaced with a
  * freshly minted one — correlation with that particular client is lost, which is strictly better
  * than a poisoned log.
  */
object RequestIds {

  val HeaderName: String = "X-Request-ID"

  /**
    * Comfortably fits a UUID (36) or a 128-bit hex trace id (32).
    */
  private val MaxLength = 64

  /**
    * An inbound value if it is safe to reuse, else `None` — the caller then mints a fresh one.
    */
  def accept(value: String): Option[String] = Option(value).filter(isSafe)

  /**
    * A random (version 4) UUID from the calling thread's own generator (side-effecting).
    *
    * Correlation only — never an authentication or authorization value, so it needs uniqueness, not
    * unpredictability. `UUID.randomUUID()` draws from one shared, synchronized `SecureRandom`,
    * which every request thread contends on under load; `ThreadLocalRandom` has no shared state.
    */
  def newId(): String = {
    val random = ThreadLocalRandom.current()
    val msb    = (random.nextLong() & ~0xf000L) | 0x4000L                        // version 4
    val lsb    = (random.nextLong() & 0x3fffffffffffffffL) | 0x8000000000000000L // RFC 4122 variant
    new UUID(msb, lsb).toString
  }

  /**
    * A non-empty, bounded token of characters that cannot break a log line or a header: ASCII
    * alphanumerics plus `. _ - :` (the separators real-world ids use). Deliberately not
    * `isLetterOrDigit`, which would admit the whole Unicode letter range — including scripts that
    * render nothing like what a log reader would grep for.
    */
  private def isSafe(value: String): Boolean =
    value.nonEmpty && value.length <= MaxLength && value.forall(isSafeChar)

  private def isSafeChar(character: Char): Boolean =
    (character >= 'a' && character <= 'z') ||
      (character >= 'A' && character <= 'Z') ||
      (character >= '0' && character <= '9') ||
      character == '.' || character == '_' ||
      character == '-' || character == ':'

}
