package auth;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http;

/**
 * Client-certificate source and RFC 8705 thumbprint comparison shared by the
 * token pipeline ({@link auth.service.TokenAuthenticator}) and
 * {@link MtlsCertificateAction} — the Java counterpart of the Scala stack's
 * {@code auth.mtls.ClientCertificates} / {@code Mtls}.
 *
 * <p>The certificate comes from Play's TLS layer
 * ({@code req.clientCertificateChain()}) or, behind a TLS-terminating proxy,
 * from a URL-encoded PEM header ({@code X-Client-Cert}, nginx's
 * {@code $ssl_client_escaped_cert}). Only trust that header if the proxy
 * strips it from incoming traffic. An unparseable value is treated as no
 * certificate, which fails closed for bound tokens.
 */
public final class MtlsCertificates {

    private static final Logger log = LoggerFactory.getLogger(MtlsCertificates.class);

    public static final String CLIENT_CERT_HEADER = "X-Client-Cert";

    private MtlsCertificates() {}

    /** TLS-layer chain first; otherwise the proxy-forwarded PEM header. */
    public static Optional<X509Certificate> extract(Http.RequestHeader req) {
        return req.clientCertificateChain()
                .filter(chain -> !chain.isEmpty())
                .map(chain -> chain.get(0))
                .or(() -> req.header(CLIENT_CERT_HEADER).map(MtlsCertificates::parsePemCertificate));
    }

    /**
     * RFC 8705 §3: constant-time comparison of the presented certificate's
     * SHA-256 thumbprint against the token's {@code cnf.x5t#S256} value
     * (base64url). Fails closed (false) on any decoding or encoding error.
     */
    public static boolean matches(X509Certificate cert, String x5tS256) {
        try {
            byte[] presented = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            byte[] bound = Base64.getUrlDecoder().decode(x5tS256);
            return MessageDigest.isEqual(presented, bound);
        } catch (Exception e) {
            log.debug("mTLS thumbprint comparison failed: {}", e.getMessage());
            return false;
        }
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
}
