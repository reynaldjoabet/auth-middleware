package auth.service;

import java.net.URI;
import java.text.ParseException;

import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.dpop.verifiers.AccessTokenValidationException;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProofUse;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPProofException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import com.nimbusds.openid.connect.sdk.Nonce;

import auth.CaffeineDPoPSingleUseChecker;
import auth.OAuthConfig;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Validates a DPoP proof for a resource request per RFC 9449 §4.3.
 *
 * <p>Delegates the heavy lifting to Nimbus's
 * {@link DPoPProtectedResourceRequestVerifier}: typ/alg/signature against the
 * embedded jwk, {@code htm}/{@code htu} match, {@code iat} freshness window,
 * {@code ath} access-token binding, {@code cnf.jkt} thumbprint match, and
 * {@code jti} single-use via {@link CaffeineDPoPSingleUseChecker} — the same
 * checks, in the same order, as Duende's {@code DPoPProofValidator} (key checks
 * before signature; replay recorded only after everything else passed).
 *
 * <p>Two checks Nimbus leaves to us, ported from Duende:
 * <ul>
 *   <li>a proof whose {@code jwk} header carries private key material is rejected outright;</li>
 *   <li>the {@code nonce} claim is surfaced to the caller, which validates it
 *       against {@link DPoPNonceService} (stateless encrypted-timestamp nonces
 *       cannot be checked by exact-match alone).</li>
 * </ul>
 */
@Singleton
public class DPoPProofVerifier {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(DPoPProofVerifier.class);

    private final DPoPProtectedResourceRequestVerifier verifier;

    @Inject
    public DPoPProofVerifier(OAuthConfig config) {
        this(config, new CaffeineDPoPSingleUseChecker());
    }

    public DPoPProofVerifier(OAuthConfig config, SingleUseChecker<DPoPProofUse> singleUseChecker) {
        this.verifier = new DPoPProtectedResourceRequestVerifier(
                OAuthTokenValidator.ACCEPTED_ALGS,
                config.dpopClockSkewSeconds(),
                config.dpopClockSkewSeconds(),
                singleUseChecker);
    }

    public record DPoPResult(
            boolean valid,
            String jkt,        // RFC 7638 thumbprint of the proof key, to match cnf.jkt
            String nonce,      // nonce claim carried by the proof, if any
            String errorCode,
            String errorDesc) {

        public static DPoPResult ok(String jkt, String nonce) {
            return new DPoPResult(true, jkt, nonce, null, null);
        }

        public static DPoPResult fail(String code, String desc) {
            return new DPoPResult(false, null, null, code, desc);
        }
    }

    /**
     * @param method      HTTP method of the incoming request ({@code htm})
     * @param htu         scheme + host + path of the incoming request, no query/fragment
     * @param clientId    the token's {@code client_id}, namespacing jti replay detection
     * @param proofHeader raw value of the {@code DPoP} header
     * @param accessToken raw access token, for the {@code ath} binding
     * @param cnf         the {@code cnf.jkt} confirmation from the validated access token
     */
    public DPoPResult verify(String method, URI htu, String clientId, String proofHeader,
                             String accessToken, JWKThumbprintConfirmation cnf) {
        SignedJWT proof;
        try {
            proof = SignedJWT.parse(proofHeader);
        } catch (ParseException e) {
            log.debug("Malformed DPoP proof: {}", e.getMessage());
            return DPoPResult.fail("invalid_dpop_proof", "Malformed DPoP proof token");
        }

        JWK jwk = proof.getHeader().getJWK();
        if (jwk == null) {
            return DPoPResult.fail("invalid_dpop_proof", "Missing 'jwk' value");
        }
        if (jwk.isPrivate()) {
            return DPoPResult.fail("invalid_dpop_proof", "'jwk' value contains a private key");
        }

        String jkt;
        String nonce;
        try {
            jkt = jwk.computeThumbprint().toString();
            nonce = proof.getJWTClaimsSet().getStringClaim("nonce");
        } catch (JOSEException | ParseException e) {
            log.debug("DPoP proof rejected while reading key/claims: {}", e.getMessage());
            return DPoPResult.fail("invalid_dpop_proof", "Invalid DPoP proof token");
        }

        try {
            verifier.verify(
                    method,
                    htu,
                    new DPoPIssuer(new ClientID(clientId)),
                    proof,
                    new DPoPAccessToken(accessToken),
                    cnf,
                    nonce == null ? null : new Nonce(nonce));
            return DPoPResult.ok(jkt, nonce);
        } catch (InvalidDPoPProofException e) {
            log.debug("DPoP proof rejected: {}", e.getMessage());
            return DPoPResult.fail("invalid_dpop_proof", e.getMessage());
        } catch (AccessTokenValidationException e) {
            log.debug("DPoP access token binding rejected: {}", e.getMessage());
            return DPoPResult.fail("invalid_token", e.getMessage());
        } catch (JOSEException e) {
            log.debug("DPoP proof signature rejected: {}", e.getMessage());
            return DPoPResult.fail("invalid_dpop_proof", "DPoP proof signature verification failed");
        }
    }
}
