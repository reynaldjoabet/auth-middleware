package auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an endpoint as requiring a minimum ACR (Authentication Context Class Reference) level.
 * Keycloak assigns ACR levels based on the authentication method:
 * <ul>
 *   <li>Level 1: username + password</li>
 *   <li>Level 2: username + password + OTP (step-up)</li>
 * </ul>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireAcr {
    int value();
}