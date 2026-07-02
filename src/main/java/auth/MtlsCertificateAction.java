package auth;

import auth.annotation.RequireMtls;
import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Validates mTLS certificate-bound access tokens per RFC 8705.
 *
 * <p>When the AS issues a certificate-bound token it embeds
 * {@code cnf: { "x5t#S256": base64url(SHA-256(cert)) }} — exactly what
 * IdentityServer's {@code X509CertificateExtensions.CreateThumbprintCnf}
 * produces. This action recomputes the thumbprint of the certificate presented
 * on the TLS connection and compares in constant time, so a stolen token is
 * useless without the client's private key.
 *
 * <p>The certificate comes from Play's TLS layer
 * ({@code req.clientCertificateChain()}) or, behind a TLS-terminating proxy,
 * from a URL-encoded PEM header ({@code X-Client-Cert}, nginx's
 * {@code $ssl_client_escaped_cert}). Only trust that header if the proxy
 * strips it from incoming traffic.
 *
 * <p>Must be composed after {@code @RequireOAuth2}.
 */
public class MtlsCertificateAction extends Action<RequireMtls> {

    private static final Logger log = LoggerFactory.getLogger(MtlsCertificateAction.class);
    private static final String CLIENT_CERT_HEADER = "X-Client-Cert";

    @Override
    public CompletionStage<Result> call(Http.Request req) {

        Optional<Principal> principal = req.attrs().getOptional(SecurityAttrs.PRINCIPAL);
        if (principal.isEmpty()) {
            return error("No token claims found — @RequireOAuth2 must precede @RequireMtls");
        }

        String tokenThumbprint;
        try {
            Map<String, Object> cnf = principal.get().raw.getJSONObjectClaim("cnf");
            tokenThumbprint = cnf == null || cnf.get("x5t#S256") == null
                    ? null
                    : cnf.get("x5t#S256").toString();
        } catch (ParseException e) {
            return error("Invalid 'cnf' value");
        }

        if (tokenThumbprint == null) {
            if (configuration.strict()) {
                return error("This endpoint requires a certificate-bound token (cnf.x5t#S256 missing)");
            }
            return delegate.call(req); // not bound; pass through in non-strict mode
        }

        X509Certificate clientCert = extractClientCertificate(req);
        if (clientCert == null) {
            return error("Certificate-bound token presented but no client certificate was provided");
        }

        try {
            byte[] presented = MessageDigest.getInstance("SHA-256").digest(clientCert.getEncoded());
            byte[] bound = Base64.getUrlDecoder().decode(tokenThumbprint);

            if (!MessageDigest.isEqual(presented, bound)) {
                log.warn("mTLS binding mismatch [{}]: presented certificate does not match cnf.x5t#S256", req.path());
                return error("Client certificate does not match the certificate bound to this token");
            }

            Http.Request enriched = req.addAttr(
                    OAuthAttrs.MTLS_CERT_SUBJECT,
                    clientCert.getSubjectX500Principal().getName());
            return delegate.call(enriched);

        } catch (Exception e) {
            log.warn("mTLS binding verification error [{}]: {}", req.path(), e.getMessage());
            return error("Failed to verify client certificate binding");
        }
    }

    private static X509Certificate extractClientCertificate(Http.Request req) {
        return req.clientCertificateChain()
                .filter(chain -> !chain.isEmpty())
                .map(chain -> chain.get(0))
                .orElseGet(() -> fromHeader(req));
    }

    private static X509Certificate fromHeader(Http.Request req) {
        return req.header(CLIENT_CERT_HEADER)
                .map(MtlsCertificateAction::parsePemCertificate)
                .orElse(null);
    }

    private static X509Certificate parsePemCertificate(String urlEncodedPem) {
        try {
            String pem = URLDecoder.decode(urlEncodedPem, StandardCharsets.UTF_8);
            String base64 = pem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            log.debug("Unparsable {} header: {}", CLIENT_CERT_HEADER, e.getMessage());
            return null;
        }
    }

    private static CompletionStage<Result> error(String desc) {
        return CompletableFuture.completedFuture(
                Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                        "Bearer error=\"invalid_token\", error_description=\"" + desc + "\""));
    }
}
