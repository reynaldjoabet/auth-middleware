package auth.service;

import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Set;

import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import auth.OAuthConfig;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Core JWT access token validator (RFC 6750 + RFC 9068).
 *
 * <p>Validates signature (against the AS's JWKS, with key rollover handled by
 * the caching/retrying JWKS source), {@code typ=at+jwt}, issuer, audience,
 * expiry with bounded clock skew, and required claims. The signing-algorithm
 * allowlist matches Duende's {@code DPoPOptions.ProofTokenValidationParameters}:
 * RSA, RSA-PSS and ECDSA at 256/384/512 — {@code none} and HMAC are structurally
 * impossible, not just rejected.
 */
@Singleton
public class OAuthTokenValidator {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(OAuthTokenValidator.class);

    /** Same allowlist Duende ships for proof and access tokens. */
    static final Set<JWSAlgorithm> ACCEPTED_ALGS = Set.of(
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);

    private final DefaultJWTProcessor<SecurityContext> processor;

    @Inject
    public OAuthTokenValidator(OAuthConfig config) {
        try {
            JWKSource<SecurityContext> jwks = JWKSourceBuilder
                    .create(config.jwksUri().toURL())
                    .retrying(true)
                    .build();

            processor = new DefaultJWTProcessor<>();
            // RFC 9068 §2.1 — refuse anything that is not an access token (e.g. an ID token)
            processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(
                    new JOSEObjectType("at+jwt"), new JOSEObjectType("at+JWT")));
            processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ACCEPTED_ALGS, jwks));

            DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<>(
                    config.audience(),
                    new JWTClaimsSet.Builder().issuer(config.issuer()).build(),
                    Set.of("sub", "exp", "iat", "jti"));
            claimsVerifier.setMaxClockSkew((int) config.clockSkewSeconds());
            processor.setJWTClaimsSetVerifier(claimsVerifier);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid JWKS URI: " + config.jwksUri(), e);
        }
    }

    public record ValidationResult(
            boolean valid,
            JWTClaimsSet claims,   // populated on success
            String errorCode,      // RFC 6750 error code, e.g. "invalid_token"
            String errorDesc) {

        public static ValidationResult ok(JWTClaimsSet claims) {
            return new ValidationResult(true, claims, null, null);
        }

        public static ValidationResult fail(String code, String desc) {
            return new ValidationResult(false, null, code, desc);
        }
    }

    public ValidationResult validate(String rawToken) {
        try {
            return ValidationResult.ok(processor.process(rawToken, null));
        } catch (BadJOSEException e) {
            // detailed cause stays in the logs; the client gets the generic message
            // (Nimbus messages can echo expected issuer/audience — internal detail)
            log.debug("Access token rejected: {}", e.getMessage());
            return ValidationResult.fail("invalid_token", "Token validation failed");
        } catch (ParseException e) {
            log.debug("Malformed access token: {}", e.getMessage());
            return ValidationResult.fail("invalid_token", "Malformed token");
        } catch (JOSEException e) {
            log.warn("Access token processing error: {}", e.getMessage());
            return ValidationResult.fail("invalid_token", "Token signature verification failed");
        }
    }
}
