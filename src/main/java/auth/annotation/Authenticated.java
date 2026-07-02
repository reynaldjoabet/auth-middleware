package auth.annotation;

import http.actions.AuthenticatedAction;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import play.mvc.With;

/**
 * Baseline token authentication with default policy — equivalent to
 * {@code @RequireOAuth2} with no extra flags. Sets
 * {@code SecurityAttrs.PRINCIPAL} for downstream actions and the controller.
 * Put it on a controller class to protect every endpoint by default, then
 * tighten individual methods with {@link RequireScope}, {@link RequireDPoP},
 * {@link RequireStrongAuth}, …
 */
@With(AuthenticatedAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface Authenticated {}
