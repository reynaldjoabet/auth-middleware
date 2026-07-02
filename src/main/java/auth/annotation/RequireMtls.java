package auth.annotation;

import auth.MtlsCertificateAction;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import play.mvc.With;

/**
 * Enforces mTLS certificate-bound token validation (RFC 8705): the SHA-256
 * thumbprint of the client certificate presented on the TLS connection must
 * equal the token's {@code cnf.x5t#S256} claim — the same binding
 * IdentityServer creates via {@code X509CertificateExtensions.CreateThumbprintCnf}.
 * Must be composed after {@link RequireOAuth2}.
 *
 * <pre>
 *   &#64;RequireOAuth2
 *   &#64;RequireMtls(strict = true)
 *   public Result bankTransfer(...) { ... }
 * </pre>
 */
@With(MtlsCertificateAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireMtls {
    /**
     * If true, reject tokens that do NOT have cnf.x5t#S256.
     * If false, only validate the binding when the claim is present.
     */
    boolean strict() default true;
}
