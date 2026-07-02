package auth.annotation;

import http.actions.ApiKeyAction;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import play.mvc.With;

/**
 * Validates an API key from the {@code X-Api-Key} header. Keys are looked up
 * through {@code auth.ApiKeyStore} (hash the stored keys; compare in constant
 * time). Query-parameter keys are deliberately not supported — they leak into
 * access logs, proxies, and Referer headers.
 *
 * <pre>
 *   &#64;RequireApiKey
 *   public Result data(Http.Request req) { ... }
 *
 *   &#64;RequireApiKey(permissions = {"read:data", "export:data"})
 *   public Result export(Http.Request req) { ... }
 * </pre>
 */
@With(ApiKeyAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireApiKey {
    /** All listed permissions must be granted to the key. */
    String[] permissions() default {};
}
