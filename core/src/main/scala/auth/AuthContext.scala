package auth

import java.time.Instant

import scala.jdk.CollectionConverters.*

import com.nimbusds.jwt.JWTClaimsSet
import io.github.iltotore.iron.*

/**
  * The authenticated principal attached to every request that passes the middleware.
  *
  * @param subject
  *   the `sub` claim, always present (required per RFC 9068). For machine-to-machine
  *   (`client_credentials`) tokens it equals the `client_id` (RFC 9068 §2.2); a user-delegated
  *   token's `sub` identifies the user and differs from the client. Per-route "an end user must be
  *   present" is enforced by `AccessTokenAuth.requireUser` (which compares `sub` to `client_id`).
  * @param clientId
  *   the OAuth client that obtained the token (`client_id` or `azp` claim), if present
  * @param scopes
  *   granted scopes, parsed from either a space-delimited `scope` string (RFC 8693 / RFC 9068) or
  *   an `scp` string array (Okta, Entra ID)
  * @param tokenId
  *   the `jti` claim, if present — useful for audit trails and revocation
  * @param expiresAt
  *   the `exp` claim
  * @param acr
  *   the Authentication Context Class Reference the user satisfied at login; enforced per route by
  *   `AccessTokenAuth.requireAcr` (RFC 9470 step-up)
  * @param authTime
  *   when the user actually authenticated (`auth_time`), used for `max_age` freshness checks in
  *   step-up flows
  * @param confirmation
  *   the RFC 7800 `cnf` sender-constraint binding, if present: either a DPoP key thumbprint (`jkt`,
  *   RFC 9449) or a client-certificate thumbprint (`x5t#S256`, RFC 8705). The two are mutually
  *   exclusive.
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

  /**
    * Roles from the `roles` claim: a JSON array of strings, as Entra ID and most custom token
    * services issue it (a single string is read as one role). Blank entries are dropped. Parsed on
    * first use, so a context cached by the verified-token cache parses them once.
    *
    * A role in a token is a snapshot from when it was issued: removing the role from the user does
    * not remove it from tokens already out. See `auth.revocation.TokenInvalidation.Subject`.
    */
  lazy val roles: Set[Role] = AuthContext.rolesOf(claims)

  def hasRole(role: Role): Boolean = roles.contains(role)

  /**
    * The `iat` claim: when the token was issued. Compared against subject-wide revocations, which
    * reject every token a subject was issued before a cut-off.
    */
  lazy val issuedAt: Option[Instant] = Option(claims.getIssueTime).map(_.toInstant)

  /**
    * True when the token is sender-constrained via DPoP or mTLS (carries a `cnf` binding).
    */
  def isSenderConstrained: Boolean = confirmation.isDefined

  /**
    * Redacted rendering, safe for logs and audit events.
    */
  override def toString: String =
    s"AuthContext(subject=$subject, clientId=$clientId, scopes=$scopes, tokenId=$tokenId, " +
      s"expiresAt=$expiresAt, acr=$acr, senderConstrained=$isSenderConstrained)"

}

object AuthContext {

  private def rolesOf(claims: JWTClaimsSet): Set[Role] =
    (claims.getClaim("roles") match {
      case list: java.util.List[?] => list.asScala.collect { case s: String => s }.toList
      case single: String          => List(single)
      case _                       => Nil
    }).flatMap(Role.option).toSet

  /**
    * Default "is an end user present?" test used by `AccessTokenAuth.requireUser`.
    *
    * A user-delegated token's `sub` identifies the user and differs from the client; a
    * `client_credentials` (M2M) token's `sub` equals its `client_id` (RFC 9068 §2.2). Override with
    * an authorization-server-specific signal (e.g. requiring `auth_time`/`acr`, or a user-only
    * scope) if your AS sets `sub = client_id` on user tokens.
    */
  val userPresent: AuthContext => Boolean = ctx =>
    !ctx.clientId.exists(c => (c.value: String) == (ctx.subject.value: String))

}
