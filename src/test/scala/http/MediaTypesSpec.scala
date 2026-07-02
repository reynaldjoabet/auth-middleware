package http

import java.util.Optional

import munit.FunSuite

class MediaTypesSpec extends FunSuite {

  test("normalize strips parameters and lowercases") {
    assertEquals(
      MediaTypes.normalize("Application/JSON; charset=UTF-8"),
      Optional.of("application/json")
    )
    assertEquals(
      MediaTypes.normalize("  multipart/form-data; boundary=----x  "),
      Optional.of("multipart/form-data")
    )
  }

  test("normalize rejects missing or malformed values") {
    assertEquals(MediaTypes.normalize(null), Optional.empty[String]())
    assertEquals(MediaTypes.normalize(""), Optional.empty[String]())
    assertEquals(MediaTypes.normalize("   "), Optional.empty[String]())
    assertEquals(MediaTypes.normalize("json"), Optional.empty[String]())
    assertEquals(MediaTypes.normalize("application/"), Optional.empty[String]())
    assertEquals(MediaTypes.normalize("/json"), Optional.empty[String]())
  }

  test("matches on exact type, ignoring parameters and case") {
    val allowed = Array("application/json")
    assertEquals(MediaTypes.matches("application/json", allowed), true)
    assertEquals(MediaTypes.matches("Application/Json; charset=utf-8", allowed), true)
    assertEquals(MediaTypes.matches("text/plain", allowed), false)
  }

  test("supports type/* and */* wildcards on the allowed side") {
    assertEquals(MediaTypes.matches("application/xml", Array("application/*")), true)
    assertEquals(MediaTypes.matches("text/xml", Array("application/*")), false)
    assertEquals(MediaTypes.matches("image/png", Array("*/*")), true)
  }

  test("a missing or malformed Content-Type never matches") {
    val allowed = Array("application/json", "*/*")
    assertEquals(MediaTypes.matches(null, allowed), false)
    assertEquals(MediaTypes.matches("", allowed), false)
    assertEquals(MediaTypes.matches("not-a-media-type", allowed), false)
  }
}
