package auth

import java.time.Instant
import com.nimbusds.jwt.JWTClaimsSet
import io.github.iltotore.iron.*

/** The authenticated principal attached to every request that passes the
  * middleware.
  *
  * @param subject
  *   the `sub` claim, always present (required per RFC 9068). For
  *   machine-to-machine (`client_credentials`) tokens it equals the `client_id`
  *   (RFC 9068 §2.2); a user-delegated token's `sub` identifies the user and
  *   differs from the client. Per-route "an end user must be present" is
  *   enforced by [[BearerAuth.requireUser]] (which compares `sub` to
  *   `client_id`).
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
  * @param confirmation
  *   the RFC 7800 `cnf` sender-constraint binding, if present: either a DPoP
  *   key thumbprint (`jkt`, RFC 9449) or a client-certificate thumbprint
  *   (`x5t#S256`, RFC 8705). The two are mutually exclusive.
  * @param claims
  *   the full validated claims set, for access to custom claims
  */
final case class AuthContext(
    subject: Subject,
    clientId: Option[ClientId],
    scopes: Set[ScopeToken],
    tokenId: Option[ReceivedJwtId],
    expiresAt: Instant,
    acr: Option[Acr],
    authTime: Option[Instant],
    confirmation: Option[
      ConfirmationClaim
    ], // the two loose dpopKeyThumbprint/certificateThumbprint: Option[String] fields collapsed into one confirmation: Option[ConfirmationClaim]. The enum makes it impossible to represent both or neither binding — a class of bug the two-Option shape allowed.
    claims: JWTClaimsSet
) {
  def hasScope(scope: ScopeToken): Boolean = scopes.contains(scope)

  /** True when the token is sender-constrained via DPoP or mTLS (carries a
    * `cnf` binding).
    */
  def isSenderConstrained: Boolean = confirmation.isDefined

  /** Redacted rendering, safe for logs and audit events. */
  override def toString: String =
    s"AuthContext(subject=$subject, clientId=$clientId, scopes=$scopes, tokenId=$tokenId, " +
      s"expiresAt=$expiresAt, acr=$acr, senderConstrained=$isSenderConstrained)"
}

object AuthContext {

  /** Default "is an end user present?" test used by [[BearerAuth.requireUser]].
    *
    * A user-delegated token's `sub` identifies the user and differs from the
    * client; a `client_credentials` (M2M) token's `sub` equals its `client_id`
    * (RFC 9068 §2.2). Override with an authorization-server-specific signal
    * (e.g. requiring `auth_time`/`acr`, or a user-only scope) if your AS sets
    * `sub = client_id` on user tokens.
    */
  val userPresent: AuthContext => Boolean = ctx =>
    !ctx.clientId.exists(c => (c.value: String) == (ctx.subject.value: String))
}
