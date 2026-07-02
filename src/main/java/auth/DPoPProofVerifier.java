package auth;


// import com.auth0.jwt.JWT;
// import com.auth0.jwt.interfaces.DecodedJWT;
// import jakarta.inject.Inject;
// import jakarta.inject.Singleton;
// import play.Logger;
// import play.mvc.Http;

// import java.nio.charset.StandardCharsets;
// import java.security.MessageDigest;
// import java.time.Instant;
// import java.time.temporal.ChronoUnit;
// import java.util.Base64;
// import java.util.Map;
// import java.util.Optional;

// /**
//  * Validates a DPoP proof header per RFC 9449.
//  *
//  * Checks:
//  *  1. typ = "dpop+jwt"
//  *  2. jwk header present (public key embedded in proof itself)
//  *  3. htm = HTTP method
//  *  4. htu = HTTP URI (scheme + host + path, no query)
//  *  5. iat is recent (within proof lifetime window, default 60s)
//  *  6. jti uniqueness (replay prevention — requires nonce store)
//  *  7. ath = base64url(SHA-256(access_token)) — binds proof to token
//  */
// @Singleton
// public class DPoPProofVerifier {

//     private static final Logger.ALogger log = Logger.of(DPoPProofVerifier.class);
//     private static final long PROOF_LIFETIME_SECONDS = 60;

//     private final DPoPNonceStore nonceStore; // prevents replay attacks
//     private final OAuthConfig config;

//     @Inject
//     public DPoPProofVerifier(DPoPNonceStore nonceStore, OAuthConfig config) {
//         this.nonceStore = nonceStore;
//         this.config = config;
//     }

//     public record DPoPResult(
//         boolean valid,
//         String jkt,          // JWK thumbprint of the key in the proof (to match cnf.jkt)
//         String errorCode,
//         String errorDesc
//     ) {
//         public static DPoPResult ok(String jkt) {
//             return new DPoPResult(true, jkt, null, null);
//         }
//         public static DPoPResult fail(String code, String desc) {
//             return new DPoPResult(false, null, code, desc);
//         }
//     }

//     /**
//      * @param proofHeader  the raw DPoP header value
//      * @param req          the incoming HTTP request (for htm/htu validation)
//      * @param accessToken  the raw Bearer token (for ath claim binding)
//      */
//     public DPoPResult validate(String proofHeader, Http.Request req, String accessToken) {
//         try {
//             DecodedJWT proof = JWT.decode(proofHeader);

//             // 1. Check typ = "dpop+jwt"
//             String typ = proof.getHeaderClaim("typ").asString();
//             if (!"dpop+jwt".equals(typ)) {
//                 return DPoPResult.fail("invalid_dpop_proof", "Expected typ=dpop+jwt, got: " + typ);
//             }

//             // 2. Check jwk is present in header (the public key that signed this proof)
//             if (proof.getHeaderClaim("jwk").isNull()) {
//                 return DPoPResult.fail("invalid_dpop_proof", "Missing jwk in DPoP proof header");
//             }
//             Map<String, Object> jwk = proof.getHeaderClaim("jwk").asMap();

//             // 3. Verify the proof signature using the embedded JWK public key
//             // (In production, deserialize the JWK and build an Algorithm from it)
//             verifyProofSignatureWithEmbeddedKey(proofHeader, jwk);

//             // 4. htm must match HTTP method
//             String htm = proof.getClaim("htm").asString();
//             if (!req.method().equalsIgnoreCase(htm)) {
//                 return DPoPResult.fail("invalid_dpop_proof",
//                     "htm mismatch: expected " + req.method() + " got " + htm);
//             }

//             // 5. htu must match request URI (scheme + host + path, strip query/fragment)
//             String htu = proof.getClaim("htu").asString();
//             String expectedHtu = buildHtu(req);
//             if (!expectedHtu.equalsIgnoreCase(htu)) {
//                 return DPoPResult.fail("invalid_dpop_proof",
//                     "htu mismatch: expected " + expectedHtu + " got " + htu);
//             }

//             // 6. iat must be within the proof lifetime window (prevents replay)
//             Long iat = proof.getClaim("iat").asLong();
//             if (iat == null) {
//                 return DPoPResult.fail("invalid_dpop_proof", "Missing iat claim in DPoP proof");
//             }
//             Instant issuedAt = Instant.ofEpochSecond(iat);
//             Instant now = Instant.now();
//             if (issuedAt.isBefore(now.minus(PROOF_LIFETIME_SECONDS, ChronoUnit.SECONDS))
//                     || issuedAt.isAfter(now.plus(config.clockSkewSeconds(), ChronoUnit.SECONDS))) {
//                 return DPoPResult.fail("invalid_dpop_proof",
//                     "DPoP proof iat is outside acceptable window");
//             }

//             // 7. jti must be unique (replay prevention)
//             String jti = proof.getId();
//             if (jti == null || jti.isBlank()) {
//                 return DPoPResult.fail("invalid_dpop_proof", "Missing jti in DPoP proof");
//             }
//             if (nonceStore.hasBeenUsed(jti)) {
//                 return DPoPResult.fail("invalid_dpop_proof",
//                     "DPoP proof jti has already been used (replay detected)");
//             }
//             nonceStore.markUsed(jti, PROOF_LIFETIME_SECONDS);

//             // 8. ath = base64url(SHA-256(ASCII(access_token))) — RFC 9449 §4.2
//             String ath = proof.getClaim("ath").asString();
//             if (ath == null) {
//                 return DPoPResult.fail("invalid_dpop_proof", "Missing ath claim in DPoP proof");
//             }
//             String expectedAth = computeAth(accessToken);
//             if (!expectedAth.equals(ath)) {
//                 return DPoPResult.fail("invalid_dpop_proof",
//                     "ath mismatch: DPoP proof is not bound to this access token");
//             }

//             // Compute JWK thumbprint (RFC 7638) for later cnf.jkt matching
//             String jkt = computeJwkThumbprint(jwk);
//             return DPoPResult.ok(jkt);

//         } catch (Exception e) {
//             log.warn("DPoP proof validation error: {}", e.getMessage());
//             return DPoPResult.fail("invalid_dpop_proof", "DPoP proof could not be parsed");
//         }
//     }

//     /** htu = scheme + "://" + host + path (no query, no fragment) — RFC 9449 §4.2 */
//     private String buildHtu(Http.Request req) {
//         String scheme = req.secure() ? "https" : "http";
//         String host   = req.host();
//         String path   = req.path();
//         return scheme + "://" + host + path;
//     }

//     /** ath = BASE64URL(SHA-256(ASCII(access_token))) */
//     private String computeAth(String accessToken) throws Exception {
//         MessageDigest digest = MessageDigest.getInstance("SHA-256");
//         byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
//         return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
//     }

//     /** JWK thumbprint per RFC 7638 (required fields vary by key type) */
//     private String computeJwkThumbprint(Map<String, Object> jwk) throws Exception {
//         // In production: serialize canonical JWK JSON → SHA-256 → base64url
//         // Using a library like Nimbus JOSE+JWT: new JWK(...).computeThumbprint()
//         String canonical = buildCanonicalJwk(jwk);
//         MessageDigest digest = MessageDigest.getInstance("SHA-256");
//         byte[] hash = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
//         return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
//     }

//     private String buildCanonicalJwk(Map<String, Object> jwk) {
//         // RFC 7638: lexicographic order of required members by key type
//         // For RSA: {"e":...,"kty":"RSA","n":...}
//         // For EC:  {"crv":...,"kty":"EC","x":...,"y":...}
//         String kty = (String) jwk.get("kty");
//         return switch (kty) {
//             case "RSA" -> String.format("{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}",
//                 jwk.get("e"), jwk.get("n"));
//             case "EC"  -> String.format("{\"crv\":\"%s\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}",
//                 jwk.get("crv"), jwk.get("x"), jwk.get("y"));
//             default    -> throw new IllegalArgumentException("Unsupported key type: " + kty);
//         };
//     }

//     private void verifyProofSignatureWithEmbeddedKey(String proof, Map<String, Object> jwk) {
//         // Production: use Nimbus JOSE+JWT or auth0/java-jwt to reconstruct the
//         // public key from the JWK map and verify the proof's signature
//         // e.g.: RSAKey rsaKey = RSAKey.parse(new JSONObject(jwk));
//         //       JWTClaimsSet claims = SignedJWT.parse(proof).verify(new RSASSAVerifier(rsaKey));
//     }
// }

public class DPoPProofVerifier{}