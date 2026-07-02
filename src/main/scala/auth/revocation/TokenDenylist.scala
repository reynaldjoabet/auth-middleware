package auth
package revocation

import cats.Applicative

/** Revocation check, consulted after a token has passed cryptographic and
  * claims validation. Back this with Redis or a database keyed by `jti` to
  * support immediate token revocation (account compromise, employee
  * offboarding, fraud holds) without waiting for the token to expire.
  *
  * Keep `jti` in [[AuthConfig.requiredClaims]] (the default does) so tokens
  * cannot dodge the check by omitting it.
  */
trait TokenDenylist[F[_]] {
  def isRevoked(tokenId: String): F[Boolean]
}

object TokenDenylist {
  def none[F[_]: Applicative]: TokenDenylist[F] = new TokenDenylist[F] {
    def isRevoked(tokenId: String): F[Boolean] = Applicative[F].pure(false)
  }
}
