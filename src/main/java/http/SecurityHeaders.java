package http;

/**
 * Response header values for {@code @NoStore}. RFC 6749 §5.1 requires
 * {@code Cache-Control: no-store} on any response containing tokens; {@code private}
 * additionally stops shared caches that ignore no-store, and {@code Pragma: no-cache}
 * covers HTTP/1.0 intermediaries (RFC 6749 §5.1 mandates it alongside Cache-Control).
 */
public final class SecurityHeaders {

  private SecurityHeaders() {}

  public static final String CACHE_CONTROL = "Cache-Control";
  public static final String PRAGMA = "Pragma";

  public static final String CACHE_CONTROL_NO_STORE = "no-store, private";
  public static final String PRAGMA_NO_CACHE = "no-cache";
}
