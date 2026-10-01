package bench

import java.util.concurrent.TimeUnit

import auth.CredentialExtraction
import org.openjdk.jmh.annotations.*
import org.openjdk.jmh.infra.Blackhole

/**
  * The `Authorization` fast path on one realistic header (`Bearer` + an 850-character JWT), against
  * the character-range scan it replaced. It runs on every request, over every character of the
  * token, so a profile of the service put it near 4% of CPU before it used lookup tables.
  *
  * {{{
  *   bench/Jmh/run -i 5 -wi 3 -f 1 .*CredentialExtractionBench.*
  * }}}
  */
@State(Scope.Benchmark)
@BenchmarkMode(Array(Mode.Throughput))
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(1)
class CredentialExtractionBench {

  private val alphabet =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

  private def segment(length: Int, seed: Long): String = {
    val random = new java.util.Random(seed)
    Array.fill(length)(alphabet.charAt(random.nextInt(alphabet.length))).mkString
  }

  // header.payload.signature, sized like an RS256 access token with a few claims
  private val header: String =
    "Bearer " + segment(36, 1) + "." + segment(330, 2) + "." + segment(342, 3)

  // Rejected at the last character, so the scan does all its work and copies nothing.
  private val rejected: String = header + " "

  @Benchmark
  def tables(bh: Blackhole): Unit = bh.consume(CredentialExtraction.fastTokenCredentials(header))

  @Benchmark
  def charRanges(bh: Blackhole): Unit = bh.consume(CredentialExtractionBench.reference(header))

  @Benchmark
  def tablesRejected(bh: Blackhole): Unit =
    bh.consume(CredentialExtraction.fastTokenCredentials(rejected))

  @Benchmark
  def charRangesRejected(bh: Blackhole): Unit =
    bh.consume(CredentialExtractionBench.reference(rejected))

}

object CredentialExtractionBench {

  // The fast path as it was before the lookup tables: a chain of range comparisons per character,
  // and both parts copied out before either is checked.
  private def isAlpha(c: Char): Boolean = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
  private def isDigit(c: Char): Boolean = c >= '0' && c <= '9'

  private def isTchar(c: Char): Boolean =
    isAlpha(c) || isDigit(c) || "!#$%&'*+-.^_`|~".indexOf(c.toInt) >= 0

  private def isT68(c: Char): Boolean =
    isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/'

  private def isToken(s: String): Boolean = s.nonEmpty && s.forall(isTchar)

  private def isToken68(s: String): Boolean = {
    var i = 0
    while (i < s.length && isT68(s.charAt(i))) i += 1
    if (i == 0) false
    else {
      while (i < s.length && s.charAt(i) == '=') i += 1
      i == s.length
    }
  }

  def reference(raw: String): Option[(String, String)] = {
    val space = raw.indexOf(' ')
    if (space <= 0) None
    else {
      val scheme = raw.substring(0, space)
      val token  = raw.substring(space + 1)
      if (isToken(scheme) && isToken68(token)) Some((scheme, token)) else None
    }
  }

}
