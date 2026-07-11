package auth;

import auth.annotation.RequireMtls;
import java.security.cert.X509Certificate;
import java.text.ParseException;
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
 * <p>The certificate source and thumbprint comparison live in
 * {@link MtlsCertificates}, shared with the token pipeline (which already
 * enforces the binding for every {@code cnf.x5t#S256} token it sees); this
 * action remains for {@code strict = true} — requiring that a route only ever
 * accepts certificate-bound tokens.
 *
 * <p>Must be composed after {@code @RequireOAuth2}.
 */
public class MtlsCertificateAction extends Action<RequireMtls> {

    private static final Logger log = LoggerFactory.getLogger(MtlsCertificateAction.class);

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

        Optional<X509Certificate> clientCert = MtlsCertificates.extract(req);
        if (clientCert.isEmpty()) {
            return error("Certificate-bound token presented but no client certificate was provided");
        }

        if (!MtlsCertificates.matches(clientCert.get(), tokenThumbprint)) {
            log.warn("mTLS binding mismatch [{}]: presented certificate does not match cnf.x5t#S256", req.path());
            return error("Client certificate does not match the certificate bound to this token");
        }

        Http.Request enriched = req.addAttr(
                OAuthAttrs.MTLS_CERT_SUBJECT,
                clientCert.get().getSubjectX500Principal().getName());
        return delegate.call(enriched);
    }

    private static CompletionStage<Result> error(String desc) {
        return CompletableFuture.completedFuture(
                Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                        "Bearer error=\"invalid_token\", error_description=\"" + desc + "\""));
    }
}
