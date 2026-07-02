package auth.annotation;

//import play.mvc.With;
import java.lang.annotation.*;

/**
 * Enforces mTLS certificate-bound token validation (RFC 8705).
 * Must be composed with @RequireOAuth2.
 *
 *   @RequireOAuth2
 *   @RequireMtls(strict = true)
 *   public Result bankTransfer(...) { ... }
 */
//@With(MtlsCertificateAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireMtls {
    /**
     * If true, reject tokens that do NOT have cnf.x5t#S256.
     * If false, only validate if the claim is present.
     */
    boolean strict() default true;
}