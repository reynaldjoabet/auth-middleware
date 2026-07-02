package auth.annotation;

//import play.mvc.With;
import java.lang.annotation.*;

/**
 * Validates fine-grained authorization_details from the token.
 * Used in Open Banking, PSD2, healthcare APIs where coarse scopes
 * are insufficient — you need to know WHAT was authorized.
 *
 * RFC 9396 — Rich Authorization Requests (RAR)
 *
 * Example token authorization_details claim:
 * [
 *   {
 *     "type": "payment_initiation",
 *     "actions": ["initiate"],
 *     "locations": ["https://api.bank.example"],
 *     "instructedAmount": { "currency": "EUR", "amount": "123.50" }
 *   }
 * ]
 *
 * Usage:
 *   @RequireOAuth2
 *   @RequireAuthzDetail(type = "payment_initiation", actions = {"initiate"})
 *   public Result initiatePayment(...) { ... }
 */
//@With(AuthzDetailAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireAuthzDetail {
    /** The authorization_details type field to match */
    String type();

    /** Required actions within that type (all must be present) */
    String[] actions() default {};

    /** Required locations (resource server URIs) */
    String[] locations() default {};
}