package auth.annotation;
//import play.mvc.With;
import java.lang.annotation.*;

/**
 * Validates the OAuth2 access token on the request.
 * Supports both Bearer (RFC 6750) and DPoP (RFC 9449) token types.
 *
 * After successful validation, the following attrs are available:
 *   OAuthAttrs.SUBJECT, OAuthAttrs.SCOPES, OAuthAttrs.CLIENT_ID, etc.
 *
 * Usage:
 *   @RequireOAuth2
 *   public Result profile(Http.Request req) {
 *       String sub = req.attrs().get(OAuthAttrs.SUBJECT);
 *   }
 */

//@With(OAuthTokenAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireOAuth2 {

    /**
     * If true, ONLY DPoP-bound tokens are accepted (RFC 9449).
     * Bearer tokens without DPoP binding will be rejected.
     * Use for high-security endpoints.
     */
    boolean requireDPoP() default false;

    /**
     * If true, validates the token is not on the revocation list
     * via the AS's introspection endpoint (RFC 7662).
     * More secure but adds latency. Use for sensitive operations.
     */
    boolean introspect() default false;
}