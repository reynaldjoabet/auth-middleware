package http

import http.BodyLimits.Verdict
import munit.FunSuite

class BodyLimitsSpec extends FunSuite {

  test("declared length within the limit passes the precheck") {
    assertEquals(BodyLimits.checkDeclaredLength("1024", 65536L), Verdict.WITHIN_LIMIT)
    assertEquals(BodyLimits.checkDeclaredLength("65536", 65536L), Verdict.WITHIN_LIMIT)
    assertEquals(BodyLimits.checkDeclaredLength(" 42 ", 65536L), Verdict.WITHIN_LIMIT)
    assertEquals(BodyLimits.checkDeclaredLength("0", 65536L), Verdict.WITHIN_LIMIT)
  }

  test("declared length over the limit is rejected") {
    assertEquals(BodyLimits.checkDeclaredLength("65537", 65536L), Verdict.EXCEEDS_LIMIT)
    assertEquals(
      BodyLimits.checkDeclaredLength(String.valueOf(Long.MaxValue), 65536L),
      Verdict.EXCEEDS_LIMIT
    )
  }

  test("absent, malformed, or negative Content-Length defers to the body parser") {
    assertEquals(BodyLimits.checkDeclaredLength(null, 65536L), Verdict.UNKNOWN)
    assertEquals(BodyLimits.checkDeclaredLength("", 65536L), Verdict.UNKNOWN)
    assertEquals(BodyLimits.checkDeclaredLength("  ", 65536L), Verdict.UNKNOWN)
    assertEquals(BodyLimits.checkDeclaredLength("12abc", 65536L), Verdict.UNKNOWN)
    assertEquals(BodyLimits.checkDeclaredLength("-1", 65536L), Verdict.UNKNOWN)
  }
}
