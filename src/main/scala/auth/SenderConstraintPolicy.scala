package auth

/** How strictly the middleware demands proof-of-possession (sender-constrained)
  * access tokens.
  *
  * A token carrying a `cnf` confirmation claim is *always* checked against the
  * matching mechanism — a DPoP-bound token presented without a valid proof, or
  * a certificate-bound token presented on a connection without the matching
  * client certificate, is rejected regardless of policy. The policy only
  * controls whether plain bearer tokens (no `cnf` claim at all) are still
  * acceptable.
  *
  * DPoP vs mTLS is not a wash. The FAPI 2.0 formal analysis (DPoP Proof Replay)
  * shows nonce-less DPoP is replayable: an attacker who reads a leaked resource
  * request — or blocks the honest one so the RS never sees it — can present the
  * proof over its own TLS connection, and per-node jti single-use detection
  * cannot fire on a request the RS never received. The mitigation is
  * RS-provided nonces ([[dpop.DpopNonceValidator]]). mTLS sender-constraining
  * has no such gap: the attacker cannot open an mTLS connection with the
  * client's key, so a stolen certificate-bound token is unusable. Prefer mTLS,
  * or DPoP *with* enforced nonces, for the highest-value resources.
  */

enum SenderConstraintPolicy derives CanEqual {

  /** Enforce bindings when the token carries them, but still accept plain
    * bearer tokens. Appropriate while migrating clients to DPoP/mTLS.
    */
  case EnforceWhenBound

  /** Every token must be sender-constrained (DPoP per RFC 9449 or mTLS per RFC
    * 8705). This is what FAPI 2.0 requires of resource servers handling
    * financial-grade or government data: a stolen token is useless without the
    * client's private key or certificate.
    */
  case Required
}
