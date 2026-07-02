package auth.annotation;

//import auth.RequireStrongAuthAction;
//import play.mvc.With;
import java.lang.annotation.*;

//@With(RequireStrongAuthAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireStrongAuth {
    /** acr advertised back to the client on step-up. */
    String acr() default "https://refeds.org/profile/mfa";
    /** Any of these amr values satisfies the policy (passkey by default). */
    String[] amr() default {"webauthn", "hwk"};
}
