package auth;


// import com.auth0.jwt.interfaces.DecodedJWT;
// import jakarta.inject.Inject;
// import play.mvc.*;

// import java.security.MessageDigest;
// import java.security.cert.X509Certificate;
// import java.util.Base64;
// import java.util.Map;
// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// /**
//  * Validates mTLS certificate-bound access tokens per RFC 8705.
//  *
//  * When the AS issues a token bound to a client certificate,
//  * it embeds the certificate thumbprint in the cnf.x5t#S256 claim.
//  * This action verifies the presented client certificate matches
//  * that thumbprint — so stolen tokens are useless without the cert.
//  *
//  * TLS termination must forward the client cert as a request attribute
//  * or header (e.g. X-Client-Cert or via play's ssl-config).
//  *
//  * Must be composed with @RequireOAuth2:
//  *   @RequireOAuth2
//  *   @RequireMtls
//  *   public Result sensitiveEndpoint(...) { ... }
//  */
// public class MtlsCertificateAction extends Action<RequireMtls> {

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {

//         // Step 1: Token must have been validated already — get its claims
//         if (!req.attrs().containsKey(OAuthAttrs.ALL_CLAIMS)) {
//             return error("invalid_token", "Token claims not found — @RequireOAuth2 must precede @RequireMtls");
//         }

//         Map<String, Object> claims = req.attrs().get(OAuthAttrs.ALL_CLAIMS);
//         Map<String, Object> cnf = (Map<String, Object>) claims.get("cnf");

//         if (cnf == null || !cnf.containsKey("x5t#S256")) {
//             // Token is not certificate-bound — reject if strict mode
//             if (configuration.strict()) {
//                 return error("invalid_token",
//                         "This endpoint requires a certificate-bound token (cnf.x5t#S256 missing)");
//             }
//             return delegate.call(req); // not bound, pass through in non-strict mode
//         }

//         String tokenCertThumbprint = (String) cnf.get("x5t#S256");

//         // Step 2: Extract the client certificate from the request
//         // In Play with SSL, client certs come via clientCertificateChain()
//         // Behind a reverse proxy, it may come as a PEM header (X-Client-Cert)
//         X509Certificate clientCert = extractClientCertificate(req);

//         if (clientCert == null) {
//             return error("invalid_token",
//                     "mTLS certificate-bound token presented but no client certificate was provided");
//         }

//         // Step 3: Compute SHA-256 thumbprint of the presented certificate
//         // and compare with cnf.x5t#S256 in the token
//         try {
//             MessageDigest digest = MessageDigest.getInstance("SHA-256");
//             byte[] certHash = digest.digest(clientCert.getEncoded());
//             String certThumbprint = Base64.getUrlEncoder()
//                     .withoutPadding()
//                     .encodeToString(certHash);

//             if (!certThumbprint.equals(tokenCertThumbprint)) {
//                 return error("invalid_token",
//                         "Client certificate does not match the certificate bound to this token");
//             }

//             // Attach the verified certificate subject to the request
//             Http.Request enriched = req.addAttr(
//                     OAuthAttrs.MTLS_CERT_SUBJECT,
//                     clientCert.getSubjectX500Principal().getName());

//             return delegate.call(enriched);

//         } catch (Exception e) {
//             return error("invalid_token", "Failed to verify client certificate binding");
//         }
//     }

//     private X509Certificate extractClientCertificate(Http.Request req) {
//         // Option A: Direct TLS (Play handles SSL)
//         return req.clientCertificateChain()
//                 .filter(chain -> !chain.isEmpty())
//                 .map(chain -> chain.get(0))
//                 .orElseGet(() -> extractFromHeader(req)); // Option B: behind a proxy
//     }

//     private X509Certificate extractFromHeader(Http.Request req) {
//         // Reverse proxies (nginx, Envoy) forward the cert as a PEM header
//         return req.header("X-Client-Cert")
//                 .map(CertificateUtils::parsePemCertificate)
//                 .orElse(null);
//     }

//     private CompletionStage<Result> error(String code, String desc) {
//         return CompletableFuture.completedFuture(
//                 Results.unauthorized()
//                         .withHeader("WWW-Authenticate",
//                                 "Bearer error=\"" + code + "\", error_description=\"" + desc + "\""));
//     }
// }

public class MtlsCertificateAction {
}