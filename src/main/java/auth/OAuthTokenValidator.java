package auth;


// import com.auth0.jwt.JWT;
// import com.auth0.jwt.algorithms.Algorithm;
// import com.auth0.jwt.exceptions.*;
// import com.auth0.jwt.interfaces.DecodedJWT;
// import com.auth0.jwt.interfaces.JWTVerifier;
// import jakarta.inject.Inject;
// import jakarta.inject.Singleton;
// import play.Logger;

// import java.security.interfaces.RSAPublicKey;
// import java.time.Instant;
// import java.util.*;

// /**
//  * Core JWT access token validator.
//  * Validates: signature, expiry, issuer, audience, token type,
//  * and DPoP binding (cnf.jkt claim per RFC 9449).
//  */
// @Singleton
// public class OAuthTokenValidator {

//     private static final Logger.ALogger log = Logger.of(OAuthTokenValidator.class);

//     private final OAuthConfig config;
//     private final JwksKeyProvider jwksProvider; // fetches public keys from Authorization Server

//     @Inject
//     public OAuthTokenValidator(OAuthConfig config, JwksKeyProvider jwksProvider) {
//         this.config = config;
//         this.jwksProvider = jwksProvider;
//     }

//     public record ValidationResult(
//         boolean valid,
//         DecodedJWT jwt,       // populated on success
//         String errorCode,     // e.g. "invalid_token", "insufficient_scope"
//         String errorDesc      // human-readable description
//     ) {
//         public static ValidationResult ok(DecodedJWT jwt) {
//             return new ValidationResult(true, jwt, null, null);
//         }
//         public static ValidationResult fail(String code, String desc) {
//             return new ValidationResult(false, null, code, desc);
//         }
//     }

//     /**
//      * Validates the raw access token string.
//      * Covers: RFC 6750, RFC 9068 (JWT Profile), RFC 9449 (DPoP binding)
//      */
//     public ValidationResult validate(String rawToken, Optional<String> dpopJkt) {
//         try {
//             // Step 1: Decode without verification to get the key ID (kid)
//             DecodedJWT unverified = JWT.decode(rawToken);

//             // Step 2: Reject tokens with "none" algorithm (security: alg confusion)
//             String alg = unverified.getAlgorithm();
//             if ("none".equalsIgnoreCase(alg) || alg == null) {
//                 return ValidationResult.fail("invalid_token", "Algorithm 'none' is not permitted");
//             }

//             // Step 3: Fetch the correct public key from JWKS by kid
//             RSAPublicKey publicKey = jwksProvider.getPublicKey(unverified.getKeyId());
//             if (publicKey == null) {
//                 return ValidationResult.fail("invalid_token", "Unknown key ID: " + unverified.getKeyId());
//             }

//             // Step 4: Build verifier — validates signature, expiry, issuer, audience
//             JWTVerifier verifier = JWT.require(Algorithm.RSA256(publicKey, null))
//                 .withIssuer(config.issuer())
//                 .withAudience(config.audience())
//                 .acceptLeeway(config.clockSkewSeconds()) // RFC 7519: allow small clock skew
//                 .build();

//             DecodedJWT verified = verifier.verify(rawToken);

//             // Step 5: Validate token type = "at+JWT" (RFC 9068 §2.1)
//             String tokenType = verified.getHeaderClaim("typ").asString();
//             if (!"at+JWT".equals(tokenType)) {
//                 return ValidationResult.fail("invalid_token",
//                     "Expected typ=at+JWT, got: " + tokenType);
//             }

//             // Step 6: Validate jti is present (replay prevention foundation)
//             if (verified.getId() == null || verified.getId().isBlank()) {
//                 return ValidationResult.fail("invalid_token", "Missing jti claim");
//             }

//             // Step 7: DPoP binding check (RFC 9449 §6.1)
//             // If the AS bound this token to a DPoP key (cnf.jkt claim),
//             // we MUST verify the incoming DPoP proof matches that key.
//             if (verified.getClaim("cnf") != null && !verified.getClaim("cnf").isNull()) {
//                 Map<String, Object> cnf = verified.getClaim("cnf").asMap();
//                 String tokenJkt = (String) cnf.get("jkt"); // JWK Thumbprint
//                 if (tokenJkt != null) {
//                     if (dpopJkt.isEmpty()) {
//                         // Token is DPoP-bound but no DPoP proof was provided
//                         return ValidationResult.fail("invalid_token",
//                             "Token is DPoP-bound but no DPoP proof header was provided");
//                     }
//                     if (!tokenJkt.equals(dpopJkt.get())) {
//                         // DPoP proof key does not match the bound key
//                         return ValidationResult.fail("invalid_token",
//                             "DPoP proof JWK thumbprint does not match cnf.jkt in token");
//                     }
//                 }
//             }

//             return ValidationResult.ok(verified);

//         } catch (TokenExpiredException e) {
//             log.debug("Token expired: {}", e.getMessage());
//             return ValidationResult.fail("invalid_token", "Token has expired");
//         } catch (SignatureVerificationException e) {
//             log.warn("Token signature invalid");
//             return ValidationResult.fail("invalid_token", "Token signature verification failed");
//         } catch (InvalidClaimException e) {
//             log.debug("Token claim invalid: {}", e.getMessage());
//             return ValidationResult.fail("invalid_token", "Token claim invalid: " + e.getMessage());
//         } catch (JWTDecodeException e) {
//             log.debug("Malformed token: {}", e.getMessage());
//             return ValidationResult.fail("invalid_token", "Malformed token");
//         }
//     }
// }

public class OAuthTokenValidator{}