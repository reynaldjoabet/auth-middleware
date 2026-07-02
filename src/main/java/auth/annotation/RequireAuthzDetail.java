package auth.annotation;

import http.actions.AuthzDetailAction;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import play.mvc.With;

/**
 * Validates fine-grained authorization_details from the token.
 * Used in Open Banking, PSD2, healthcare APIs where coarse scopes
 * are insufficient — you need to know WHAT was authorized.
 *
 * RFC 9396 — Rich Authorization Requests (RAR)
 *
 * <p>Example token authorization_details claim:
 * <pre>
 * [
 *   {
 *     "type": "payment_initiation",
 *     "actions": ["initiate"],
 *     "locations": ["https://api.bank.example"],
 *     "instructedAmount": { "currency": "EUR", "amount": "123.50" }
 *   }
 * ]
 * </pre>
 *
 * Must be composed after {@link RequireOAuth2}. The matched entry is attached
 * to the request as {@code OAuthAttrs.AUTHZ_DETAIL}.
 *
 * <pre>
 *   &#64;RequireOAuth2
 *   &#64;RequireAuthzDetail(type = "payment_initiation", actions = {"initiate"})
 *   public Result initiatePayment(...) { ... }
 * </pre>
 */
@With(AuthzDetailAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireAuthzDetail {
    /** The authorization_details type field to match. */
    String type();

    /** Required actions within that type (all must be present). */
    String[] actions() default {};

    /** Required locations (resource server URIs). */
    String[] locations() default {};
}
