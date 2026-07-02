package auth

/** Outcome of a failed authentication or authorization check.
  *
  * The `reason` strings carried here are fixed, library-controlled values: they
  * are safe to return to clients in `error_description` and never contain token
  * material, claim values or upstream exception messages. Internal diagnostic
  * detail is routed separately through [[AuthEvents]] so it reaches logs and
  * metrics but never the HTTP response.
  */
enum AuthError derives CanEqual {

  /** No `Authorization` credentials were presented. */
  case MissingToken

  /** The request shape itself is unacceptable — for example the access token
    * was passed in the query string (forbidden by OAuth 2.1, and a leak vector
    * via logs, referrers and browser history) or multiple credentials were
    * supplied. RFC 6750 `invalid_request`, answered with 400.
    */
  case InvalidRequest(reason: String)

  /** The token failed structural, signature, type, claims or sender-constraint
    * validation, or has been revoked. RFC 6750 `invalid_token`.
    */
  case InvalidToken(reason: String)

  /** The DPoP proof JWT accompanying the request was missing, malformed, stale,
    * replayed or otherwise invalid. RFC 9449 `invalid_dpop_proof`.
    */
  case InvalidDpopProof(reason: String)

  /** The resource server requires a DPoP proof carrying a server-provided nonce
    * (RFC 9449 §8-9), and the proof either omitted it or presented one that is
    * unknown, expired or already used. Answered with `401`,
    * `error="use_dpop_nonce"` and a fresh `DPoP-Nonce` response header the
    * client must echo in the `nonce` claim of its next proof.
    *
    * This is the fix mandated by the FAPI 2.0 formal analysis for the DPoP
    * Proof Replay attack: without it, a network attacker who reads a leaked
    * resource request (or blocks the honest one) can replay the proof, since
    * per-node single-use detection never sees the original request. Unlike the
    * other `InvalidDpopProof*` reasons this is not really a client error — it
    * is a challenge — so it carries the nonce to hand back rather than a fixed
    * `reason` string.
    */
  case UseDpopNonce(nonce: DpopNonce)

  /** The token is valid but does not carry the scopes the route requires. RFC
    * 6750 `insufficient_scope`.
    */
  case InsufficientScope(required: Set[String])

  /** The token is valid but the user's authentication does not meet the route's
    * step-up requirements (`acr` value and/or `auth_time` freshness). RFC 9470
    * `insufficient_user_authentication`.
    *
    * `acrValues` is ordered by preference (RFC 9470 §3: the `acr_values`
    * challenge parameter lists values "in order of preference"), so it is a
    * `Seq`, not a `Set`.
    */
  case InsufficientUserAuthentication(
      acrValues: Seq[String],
      maxAge: Option[MaxAuthAge]
  )

  /** Validation could not be performed at all (for example the JWKS endpoint
    * was unreachable and no cached keys were available). The middleware fails
    * closed and answers 503 rather than guessing.
    */
  case ValidationUnavailable
}

object AuthError {

  object InvalidRequest {
    val TokenInQuery: AuthError.InvalidRequest =
      AuthError.InvalidRequest(
        "access tokens must not be sent in the query string"
      )
    val MultipleCredentials: AuthError.InvalidRequest =
      AuthError.InvalidRequest(
        "multiple authorization credentials were presented"
      )
  }

  object InvalidToken {
    val Malformed: AuthError.InvalidToken =
      AuthError.InvalidToken("token is malformed")
    val Oversized: AuthError.InvalidToken =
      AuthError.InvalidToken("token exceeds maximum permitted length")
    val Rejected: AuthError.InvalidToken =
      AuthError.InvalidToken(
        "token signature, type or claims validation failed"
      )
    val Revoked: AuthError.InvalidToken =
      AuthError.InvalidToken("token has been revoked")
    val WrongScheme: AuthError.InvalidToken =
      AuthError.InvalidToken(
        "unsupported authorization scheme, expected Bearer"
      )

    /** RFC 9449: a `cnf.jkt`-bound token must come with the `DPoP` scheme and
      * proof.
      */
    val DpopBindingRequired: AuthError.InvalidToken =
      AuthError.InvalidToken(
        "token is DPoP-bound and must be presented with the DPoP scheme and a proof"
      )

    /** The `DPoP` scheme was used with a token that carries no `cnf.jkt`
      * binding.
      */
    val NotDpopBound: AuthError.InvalidToken =
      AuthError.InvalidToken(
        "token presented with the DPoP scheme is not DPoP-bound"
      )

    /** RFC 8705: the `cnf.x5t#S256` binding did not match the client
      * certificate.
      */
    val CertificateBindingFailed: AuthError.InvalidToken =
      AuthError.InvalidToken(
        "token is bound to a client certificate that was not presented on this connection"
      )

    /** [[SenderConstraintPolicy.Required]] (FAPI 2.0): plain bearer tokens are
      * not accepted.
      */
    val SenderConstraintRequired: AuthError.InvalidToken =
      AuthError.InvalidToken(
        "this resource requires sender-constrained (DPoP or certificate-bound) access tokens"
      )
  }

  object InvalidDpopProof {
    val Missing: AuthError.InvalidDpopProof =
      AuthError.InvalidDpopProof("DPoP proof is missing")
    val Malformed: AuthError.InvalidDpopProof =
      AuthError.InvalidDpopProof("DPoP proof is malformed")
    val Rejected: AuthError.InvalidDpopProof =
      AuthError.InvalidDpopProof("DPoP proof validation failed")
    val Replayed: AuthError.InvalidDpopProof =
      AuthError.InvalidDpopProof("DPoP proof has already been used")
  }
}
