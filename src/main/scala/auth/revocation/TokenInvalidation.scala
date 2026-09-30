package auth
package revocation

import java.time.Instant

/**
  * An invalidation published by the token service, for every API that accepts its tokens to apply
  * locally (see [[InvalidationStore]] and `app.infra.kafka.KafkaInvalidations`).
  */
enum TokenInvalidation derives CanEqual {

  /**
    * One token, by `jti`, until it expires.
    */
  case Token(jti: String, expiresAt: Instant)

  /**
    * Every token `subject` was issued before `issuedBefore`. Publish this, rather than one
    * [[Token]] per outstanding token, when something about the subject changes that its tokens
    * carry: roles or groups changed, password reset, account disabled, "sign out everywhere". The
    * token service needn't track which tokens are out; the user signs in again and gets one with
    * the new roles.
    *
    * @param reason
    *   free text for audit logs (e.g. `roles-changed`); not interpreted
    */
  case Subject(subject: String, issuedBefore: Instant, reason: Option[String])

}
