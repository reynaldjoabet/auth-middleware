package http

import munit.FunSuite

class SecurityHeadersSpec extends FunSuite {

  test("@NoStore header values follow RFC 6749 §5.1") {
    assertEquals(SecurityHeaders.CACHE_CONTROL, "Cache-Control")
    assertEquals(SecurityHeaders.PRAGMA, "Pragma")
    assertEquals(SecurityHeaders.CACHE_CONTROL_NO_STORE, "no-store, private")
    assertEquals(SecurityHeaders.PRAGMA_NO_CACHE, "no-cache")
  }
}
