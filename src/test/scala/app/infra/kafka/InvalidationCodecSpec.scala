package app.infra.kafka

import java.time.Instant

import auth.revocation.TokenInvalidation
import munit.FunSuite

class InvalidationCodecSpec extends FunSuite {

  private val at = Instant.parse("2026-10-01T10:05:00Z")

  test("both kinds round-trip, with keys that keep one token or subject on one partition") {
    List(
      TokenInvalidation.Token("ABC", at),
      TokenInvalidation.Subject("u-42", at, Some("roles-changed")),
      TokenInvalidation.Subject("u-42", at, None)
    ).foreach { invalidation =>
      assertEquals(
        InvalidationCodec.decode(InvalidationCodec.encode(invalidation)),
        Right(invalidation)
      )
    }
    assertEquals(InvalidationCodec.keyOf(TokenInvalidation.Token("ABC", at)), "jti:ABC")
    assertEquals(InvalidationCodec.keyOf(TokenInvalidation.Subject("u-42", at, None)), "sub:u-42")
  }

  test("reads the documented format") {
    assertEquals(
      InvalidationCodec.decode(
        """{"type":"token","jti":"ABC","expires_at":"2026-10-01T10:05:00Z"}"""
      ),
      Right(TokenInvalidation.Token("ABC", at))
    )
    assertEquals(
      InvalidationCodec.decode(
        """{"type":"subject","sub":"u-42","issued_before":"2026-10-01T10:05:00Z","reason":"roles-changed"}"""
      ),
      Right(TokenInvalidation.Subject("u-42", at, Some("roles-changed")))
    )
  }

  test("rejects what it cannot apply safely") {
    List(
      """{"type":"token","jti":" ","expires_at":"2026-10-01T10:05:00Z"}""",
      """{"type":"token","jti":"ABC"}""",
      """{"type":"subject","sub":"u-42"}""",
      """{"type":"role","role":"Manager"}""",
      """{"jti":"ABC","expires_at":"2026-10-01T10:05:00Z"}""",
      "not json"
    ).foreach(json => assert(InvalidationCodec.decode(json).isLeft, json))
  }

}
