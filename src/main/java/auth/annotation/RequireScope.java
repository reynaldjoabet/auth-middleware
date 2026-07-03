package auth.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import http.actions.ScopeCheckAction;
import play.mvc.With;

/**
 * Validates that the token contains ALL the required scopes, represents an
 * end user (unless waived), and — optionally — that a product feature is
 * enabled for the caller. Must be composed after {@link RequireOAuth2} (or
 * {@link Authenticated}); it reads the {@code SecurityAttrs.PRINCIPAL} those
 * actions set.
 *
 * <p>Always reference scopes through {@link auth.ScopeConstants} — the
 * constants are parity-tested against the Scala catalogue, string literals
 * are not:
 *
 * <pre>
 *   &#64;Authenticated
 *   &#64;RequireScope(ScopeConstants.BILLING_INVOICES_READ)
 *   public Result invoices(Http.Request req) { ... }
 *
 *   // machine (client-credentials) endpoint:
 *   &#64;RequireScope(value = ScopeConstants.REPORTS_EXPORTS_CREATE,
 *                 requireUserIdentity = false)
 * </pre>
 *
 * <p>For AT-LEAST-ONE semantics (e.g. {@code manage} satisfying a {@code read}
 * endpoint) use {@link RequireAnyScope}.
 *
 * <p>On a missing scope this responds {@code 403} with
 * {@code WWW-Authenticate: Bearer error="insufficient_scope", scope="…"}
 * advertising the full required set (RFC 6750 §3.1); on a missing user
 * identity, {@code 403} with {@code error="insufficient_user_authentication"}
 * (RFC 9470 §3).
 */
@With(ScopeCheckAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireScope {

    /** All listed scopes must be present in the token. */
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
