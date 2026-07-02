package auth.annotation;

import http.actions.ResourceIndicatorAction;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import play.mvc.With;

/**
 * Validates that the token's {@code aud} claim contains this resource server's
 * URI (RFC 8707 — Resource Indicators). Prevents audience confusion: a token
 * issued for resource server A cannot be replayed at resource server B even
 * with identical scopes. Must be composed after {@link RequireOAuth2}.
 *
 * <pre>
 *   &#64;RequireOAuth2
 *   &#64;RequireResource("https://api.myservice.com")
 *   public Result endpoint(...) { ... }
 * </pre>
 */
@With(ResourceIndicatorAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireResource {
    /** The resource server URI that must appear in the token's aud claim. */
    String value();
}
