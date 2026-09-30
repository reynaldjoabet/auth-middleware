package auth
package dpop

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKey

/**
  * Pure DPoP helpers shared by configuration, the http4s verifier and the test fixtures.
  */
object DpopKeys {

  /**
    * Wrap AES key material for stateless nonces (16, 24 or 32 bytes).
    */
  def nonceKeyFromBytes(bytes: Array[Byte]): SecretKey = {
    require(
      Set(16, 24, 32).contains(bytes.length),
      s"AES key must be 16, 24 or 32 bytes, got ${bytes.length}"
    )
    new SecretKeySpec(bytes, "AES")
  }

  /**
    * The `ath` claim value for an access token (RFC 9449 §4.2): base64url(SHA-256(token)).
    */
  def accessTokenHash(accessToken: String): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(
      MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes(StandardCharsets.US_ASCII))
    )

}
