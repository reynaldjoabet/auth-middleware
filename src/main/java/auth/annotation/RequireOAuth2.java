package auth.annotation;

import http.actions.OAuthTokenAction;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import play.mvc.With;

/**
 * Validates the OAuth2 access token on the request.
 * Supports both Bearer (RFC 6750) and DPoP (RFC 9449) token types.
 *
 * <p>After successful validation the verified context is available as
 * {@code SecurityAttrs.PRINCIPAL} plus the individual {@code OAuthAttrs.*}
 * keys (SUBJECT, SCOPES, CLIENT_ID, …).
 *
 * <p>A token carrying a {@code cnf} confirmation claim is <em>never</em>
 * accepted over plain Bearer, even with default settings — downgrade
 * protection ported from Duende's {@code DPoPJwtBearerEvents}.
 *
 * <pre>
 *   &#64;RequireOAuth2
 *   public Result profile(Http.Request req) {
 *       Principal p = req.attrs().get(SecurityAttrs.PRINCIPAL);
 *   }
 * </pre>
 */
@With(OAuthTokenAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireOAuth2 {

    /**
     * If true, ONLY DPoP-bound tokens are accepted (RFC 9449); plain Bearer
     * presentation is rejected with a {@code DPoP} challenge. Equivalent to
     * Duende's {@code AllowBearerTokens = false}. Use for high-security endpoints.
     */
    boolean requireDPoP() default false;

    /**
     * If true, additionally validates the token against the AS's introspection
     * endpoint (RFC 7662) as a revocation check. More secure but adds a network
     * hop per request; fails closed. Use for sensitive operations.
     */
    boolean introspect() default false;
}
