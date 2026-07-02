package auth.annotation;

import http.actions.ScopeCheckAction;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import play.mvc.With;

/**
 * Validates that the token contains ALL the required scopes.
 * Must be composed after {@link RequireOAuth2} (or {@link Authenticated}).
 *
 * <p>On failure responds {@code 403} with
 * {@code WWW-Authenticate: Bearer error="insufficient_scope", scope="…"}
 * advertising the full required set (RFC 6750 §3.1).
 *
 * <pre>
 *   &#64;RequireOAuth2
 *   &#64;RequireScope({"read:orders", "read:profile"})
 *   public Result orders(Http.Request req) { ... }
 * </pre>
 */
@With(ScopeCheckAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireScope {
    /** All listed scopes must be present in the token. */
    String[] value();
}
