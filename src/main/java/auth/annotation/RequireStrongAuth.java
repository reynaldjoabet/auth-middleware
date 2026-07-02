package auth.annotation;

import http.actions.StrongAuthAction;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import play.mvc.With;

/**
 * Requires that the authentication behind the token satisfies a step-up policy:
 * either the {@code acr} matches, or any of the accepted {@code amr} values is
 * present (passkey by default). On failure responds {@code 401} with
 * {@code error="insufficient_user_authentication"} and the desired
 * {@code acr_values}, per RFC 9470 (OAuth 2.0 Step Up Authentication
 * Challenge). Must be composed after {@link RequireOAuth2}.
 */
@With(StrongAuthAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireStrongAuth {
    /** acr advertised back to the client on step-up. */
    String acr() default "https://refeds.org/profile/mfa";

    /** Any of these amr values satisfies the policy (passkey by default). */
    String[] amr() default {"webauthn", "hwk"};
}
