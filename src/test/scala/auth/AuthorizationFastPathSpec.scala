package auth

import scala.util.Random

import cats.effect.IO

import munit.FunSuite
import org.http4s.{Credentials, Header, Request}
import org.http4s.headers.Authorization
import org.typelevel.ci.*

/**
  * The hand-written `Authorization` scan must agree with http4s's typed parser on every input: it
  * is an optimisation, never a second opinion. Checked on hand-picked edge cases and on random
  * header values drawn from an alphabet that exercises every branch.
  */
class AuthorizationFastPathSpec extends FunSuite {

  private def request(raw: String): Request[IO] =
    Request[IO]().putHeaders(Header.Raw(ci"Authorization", raw))

  /**
    * What the code did before the fast path: http4s's typed lookup alone.
    */
  private def reference(raw: String): Option[Option[(String, String)]] =
    request(raw).headers.get[Authorization].map {
      // CIString keeps the original text, so toString is the scheme as sent.
      case Authorization(Credentials.Token(scheme, token)) => Some((scheme.toString, token))
      case _                                               => None
    }

  private def assertAgrees(raw: String): Unit =
    assertEquals(AccessTokenAuth.tokenCredentials(request(raw)), reference(raw), s"input: [$raw]")

  private val edgeCases = List(
    "Bearer abc",
    "bearer abc",
    "BEARER abc",
    "DPoP abc.def.ghi",
    "Bearer  abc",
    "Bearer abc==",
    "Bearer a=b",
    "Bearer =",
    "Bearer ==abc",
    "Bearer abc def",
    "Bearer abc,",
    "Bearer realm=\"x\"",
    "Bearer realm=\"x\", error=\"y\"",
    "Basic dXNlcjpwYXNz",
    "Bearer",
    "Bearer ",
    " Bearer abc",
    "Bearer\tabc",
    "Bear er abc",
    "Bearer ab/c+d~e_f-g.h",
    "Bearer abcé",
    "B@arer abc",
    "Bearer abc ",
    "",
    "=",
    "Bearer a\"b",
    // auth-param forms, which exercise the full grammar's commit rules
    "Bearer a=b",
    "Bearer a=b, c=d",
    "Bearer a = b",
    "Bearer ,a=b",
    "Bearer ,, a=b",
    "Bearer a=b,",
    "Bearer a=b, ",
    "Bearer a=b ,c=d",
    "Bearer a=b,,c=d",
    "Bearer a=b,c",
    "Bearer a=b c",
    "Bearer a=\"x y\"",
    "Bearer a=\"x\\\"y\"",
    "Bearer a=\"unterminated",
    "Bearer a=\"bad\\\u0001\"",
    "Bearer a=",
    "Bearer ,",
    "Bearer abc==, d=e"
  )

  test("agrees with http4s on hand-picked edge cases") {
    edgeCases.foreach(assertAgrees)
  }

  test("agrees with http4s on 200,000 random header values") {
    val random   = new Random(20260930L)
    val alphabet = "aZ09-._~+/= ,\"\t:;é@!#\\".toVector
    val schemes  = Vector("Bearer", "bearer", "DPoP", "Basic", "x", "")
    (1 to 200_000).foreach { _ =>
      val body = Vector.fill(random.nextInt(12))(alphabet(random.nextInt(alphabet.size))).mkString
      val raw  =
        if (random.nextBoolean()) schemes(random.nextInt(schemes.size)) + " " + body else body
      assertAgrees(raw)
    }
  }

  test("a real access token takes the fast path") {
    val token = TestTokens.sign(TestTokens.claims())
    assertEquals(
      CredentialExtraction.fastTokenCredentials(s"Bearer $token"),
      Some(("Bearer", token))
    )
  }

}
