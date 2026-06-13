package auth

import java.time.Instant
import com.nimbusds.jwt.JWTClaimsSet

/** The authenticated principal attached to every request that passes the
  * middleware.
  *
  * @param subject
  *   the `sub` claim — the end user or service account the token was issued to
  * @param clientId
  *   the OAuth client that obtained the token (`client_id` or `azp` claim), if
  *   present
  * @param scopes
  *   granted scopes, parsed from either a space-delimited `scope` string (RFC
  *   8693 / RFC 9068) or an `scp` string array (Okta, Entra ID)
  * @param tokenId
  *   the `jti` claim, if present — useful for audit trails and revocation
  * @param expiresAt
  *   the `exp` claim
  * @param acr
  *   the Authentication Context Class Reference the user satisfied at login;
  *   enforced per route by [[BearerAuth.requireAcr]] (RFC 9470 step-up)
  * @param authTime
  *   when the user actually authenticated (`auth_time`), used for `max_age`
  *   freshness checks in step-up flows
  * @param dpopKeyThumbprint
  *   the `cnf.jkt` confirmation claim (RFC 9449): the JWK SHA-256 thumbprint of
  *   the DPoP key this token is bound to
  * @param certificateThumbprint
  *   the `cnf.x5t#S256` confirmation claim (RFC 8705): the SHA-256 thumbprint
  *   of the client certificate this token is bound to
  * @param claims
  *   the full validated claims set, for access to custom claims
  */
final case class AuthContext(
    subject: String,
    clientId: Option[String],
    scopes: Set[String],
    tokenId: Option[String],
    expiresAt: Instant,
    acr: Option[String],
    authTime: Option[Instant],
    dpopKeyThumbprint: Option[String],
    certificateThumbprint: Option[String],
    claims: JWTClaimsSet
) {
  def hasScope(scope: String): Boolean = scopes.contains(scope)

  /** True when the token is sender-constrained via DPoP or mTLS (carries a
    * `cnf` binding).
    */
  def isSenderConstrained: Boolean =
    dpopKeyThumbprint.isDefined || certificateThumbprint.isDefined

  /** Redacted rendering, safe for logs and audit events. */
  override def toString: String =
    s"AuthContext(subject=$subject, clientId=$clientId, scopes=$scopes, tokenId=$tokenId, " +
      s"expiresAt=$expiresAt, acr=$acr, senderConstrained=$isSenderConstrained)"
}
