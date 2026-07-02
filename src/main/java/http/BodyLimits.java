package http;

/**
 * Content-Length precheck for {@code @MaxBodySize} (ASP.NET Core's
 * {@code [RequestSizeLimit]}): a body declared larger than the limit is rejected
 * with 413 before a single byte is read. Chunked or undeclared bodies report
 * {@link Verdict#UNKNOWN} and must be bounded by the body parser instead.
 */
public final class BodyLimits {

  private BodyLimits() {}

  public enum Verdict {
    /** Declared length is within the limit; the parser bound still applies. */
    WITHIN_LIMIT,
    /** Declared length exceeds the limit; reject with 413 without reading the body. */
    EXCEEDS_LIMIT,
    /** No usable Content-Length (absent, malformed, or negative); defer to the parser. */
    UNKNOWN
  }

  public static Verdict checkDeclaredLength(String contentLengthHeader, long maxBytes) {
    if (contentLengthHeader == null || contentLengthHeader.isBlank()) {
      return Verdict.UNKNOWN;
    }
    long declared;
    try {
      declared = Long.parseLong(contentLengthHeader.trim());
    } catch (NumberFormatException e) {
      return Verdict.UNKNOWN;
    }
    if (declared < 0) {
      return Verdict.UNKNOWN;
    }
    return declared <= maxBytes ? Verdict.WITHIN_LIMIT : Verdict.EXCEEDS_LIMIT;
  }
}
