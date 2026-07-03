package auth.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import http.actions.AnyScopeCheckAction;
import play.mvc.With;

/**
 * Validates that the token contains AT LEAST ONE of the listed scopes — the
 * OR counterpart of {@link RequireScope}, with the same user-identity and
 * feature-gate policy members. Must be composed after {@link RequireOAuth2}
 * (or {@link Authenticated}).
 *
 * <p>The canonical use is scope hierarchy: a {@code manage} scope satisfying
 * an endpoint that nominally needs {@code read}:
 *
 * <pre>
 *   &#64;Authenticated
 *   &#64;RequireAnyScope({ScopeConstants.BILLING_INVOICES_READ,
 *                     ScopeConstants.BILLING_INVOICES_MANAGE})
 *   public Result invoices(Http.Request req) { ... }
 * </pre>
 *
 * <p>On failure responds {@code 403} with
 * {@code WWW-Authenticate: Bearer error="insufficient_scope"} advertising
 * every acceptable scope (RFC 6750 §3.1) — the client may obtain any of them.
 *
 * <p>An empty list can never match and therefore rejects every request:
 * misconfiguration fails closed.
 */
@With(AnyScopeCheckAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireAnyScope {

    /** At least one listed scope must be present in the token. */
    String[] value();

    /**
     * When {@code true} (the default) the token must represent an end user:
     * a non-blank {@code sub} distinct from {@code client_id}. Endpoints that
     * machine (client-credentials) tokens may call must opt out explicitly.
     */
    boolean requireUserIdentity() default true;

    /**
     * Optional product-feature gate, resolved through
     * {@link auth.FeatureChecker} after the token checks pass. Empty (the
     * default) means no feature check.
     */
    String requiredFeature() default "";
}
