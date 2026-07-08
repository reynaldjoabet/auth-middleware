package auth
package revocation
import auth.revocation.TokenDenylist

import cats.effect.IO
import munit.CatsEffectSuite

class TokenDenylistSpec extends CatsEffectSuite {

  test("none never reports a token as revoked") {
    val denylist = TokenDenylist.none[IO]
    for {
      a <- denylist.isRevoked("jti-abc")
      b <- denylist.isRevoked("")
      c <- denylist.isRevoked("some-other-jti")
    } yield {
      assertEquals(a, false)
      assertEquals(b, false)
      assertEquals(c, false)
    }
  }
}
