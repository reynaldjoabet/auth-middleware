package auth

import scala.concurrent.duration.FiniteDuration

/** Outcome of a failed authentication or authorization check.
  *
  * The `reason` strings carried here are fixed, library-controlled values: they
  * are safe to return to clients in `error_description` and never contain token
  * material, claim values or upstream exception messages. Internal diagnostic
  * detail is routed separately through [[AuthEvents]] so it reaches logs and
  * metrics but never the HTTP response.
  */
sealed abstract class AuthError extends Product with Serializable
    derives CanEqual

object AuthError {

  /** No `Authorization` credentials were presented. */
  case object MissingToken extends AuthError

  /** The request shape itself is unacceptable — for example the access token
    * was passed in the query string (forbidden by OAuth 2.1, and a leak vector
    * via logs, referrers and browser history) or multiple credentials were
    * supplied. RFC 6750 `invalid_request`, answered with 400.
    */
  final case class InvalidRequest(reason: String) extends AuthError

  object InvalidRequest {
    val TokenInQuery: InvalidRequest =
      InvalidRequest("access tokens must not be sent in the query string")
    val MultipleCredentials: InvalidRequest =
      InvalidRequest("multiple authorization credentials were presented")
  }

  /** The token failed structural, signature, type, claims or sender-constraint
    * validation, or has been revoked. RFC 6750 `invalid_token`.
    */
  final case class InvalidToken(reason: String) extends AuthError

  object InvalidToken {
    val Malformed: InvalidToken = InvalidToken("token is malformed")
    val Oversized: InvalidToken = InvalidToken(
      "token exceeds maximum permitted length"
    )
    val Rejected: InvalidToken = InvalidToken(
      "token signature, type or claims validation failed"
    )
    val Revoked: InvalidToken = InvalidToken("token has been revoked")
    val MissingTokenId: InvalidToken = InvalidToken(
      "token is missing a jti claim"
    )
    val WrongScheme: InvalidToken = InvalidToken(
      "unsupported authorization scheme, expected Bearer"
    )

    /** RFC 9449: a `cnf.jkt`-bound token must come with the `DPoP` scheme and
      * proof.
      */
    val DpopBindingRequired: InvalidToken =
      InvalidToken(
        "token is DPoP-bound and must be presented with the DPoP scheme and a proof"
      )

    /** The `DPoP` scheme was used with a token that carries no `cnf.jkt`
      * binding.
      */
    val NotDpopBound: InvalidToken =
      InvalidToken("token presented with the DPoP scheme is not DPoP-bound")

    /** RFC 8705: the `cnf.x5t#S256` binding did not match the client
      * certificate.
      */
    val CertificateBindingFailed: InvalidToken =
      InvalidToken(
        "token is bound to a client certificate that was not presented on this connection"
      )

    /** [[SenderConstraintPolicy.Required]] (FAPI 2.0): plain bearer tokens are
      * not accepted.
      */
    val SenderConstraintRequired: InvalidToken =
      InvalidToken(
        "this resource requires sender-constrained (DPoP or certificate-bound) access tokens"
      )
  }

  /** The DPoP proof JWT accompanying the request was missing, malformed, stale,
    * replayed or otherwise invalid. RFC 9449 `invalid_dpop_proof`.
    */
  final case class InvalidDpopProof(reason: String) extends AuthError

  object InvalidDpopProof {
    val Missing: InvalidDpopProof = InvalidDpopProof("DPoP proof is missing")
    val Malformed: InvalidDpopProof = InvalidDpopProof(
      "DPoP proof is malformed"
    )
    val Rejected: InvalidDpopProof = InvalidDpopProof(
      "DPoP proof validation failed"
    )
    val Replayed: InvalidDpopProof = InvalidDpopProof(
      "DPoP proof has already been used"
    )
  }

  /** The token is valid but does not carry the scopes the route requires. RFC
    * 6750 `insufficient_scope`.
    */
  final case class InsufficientScope(required: Set[String]) extends AuthError

  /** The token is valid but the user's authentication does not meet the route's
    * step-up requirements (`acr` value and/or `auth_time` freshness). RFC 9470
    * `insufficient_user_authentication`.
    */
  final case class InsufficientUserAuthentication(
      acrValues: Set[String],
      maxAge: Option[FiniteDuration]
  ) extends AuthError

  /** Validation could not be performed at all (for example the JWKS endpoint
    * was unreachable and no cached keys were available). The middleware fails
    * closed and answers 503 rather than guessing.
    */
  case object ValidationUnavailable extends AuthError
}
