package auth.service;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import auth.OAuthConfig;

/**
 * Issues and validates server-provided DPoP nonces (RFC 9449 §8) statelessly,
 * following Duende's {@code DefaultDPoPNonceValidator}: a nonce is an AES-GCM
 * encrypted server timestamp, so validation is decrypt + freshness check. No
 * nonce store is needed, and any node sharing the key can validate a nonce any
 * other node issued.
 *
 * <p>On failure the caller must answer {@code 401 use_dpop_nonce} with a fresh
 * value in the {@code DPoP-Nonce} response header ({@link #create()}).
 */
@Singleton
public class DPoPNonceService {

    private static final Logger log = LoggerFactory.getLogger(DPoPNonceService.class);
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;
    /** Duende: ProofTokenNonceClockSkew — server-issued time needs only minimal forward leeway. */
    private static final long FORWARD_SKEW_SECONDS = 5;

    private final SecretKey key;
    private final long lifetimeSeconds;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    @Inject
    public DPoPNonceService(OAuthConfig config) {
        this(ephemeralKey(), config.nonceLifetimeSeconds(), Clock.systemUTC());
        log.warn("DPoPNonceService using an ephemeral key — nonces will not validate across "
                + "nodes or restarts. Provide a shared SecretKey in production.");
    }

    public DPoPNonceService(SecretKey key, long lifetimeSeconds, Clock clock) {
        this.key = key;
        this.lifetimeSeconds = lifetimeSeconds;
        this.clock = clock;
    }

    private static SecretKey ephemeralKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            return kg.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES unavailable", e);
        }
    }

    /** Mints a fresh nonce encoding the current server time. */
    public String create() {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(
                    Long.toString(clock.instant().getEpochSecond()).getBytes(StandardCharsets.US_ASCII));
            byte[] out = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to create DPoP nonce", e);
        }
    }

    /** True if {@code nonce} was issued by us (any node sharing the key) and is still fresh. */
    public boolean validate(String nonce) {
        try {
            byte[] in = Base64.getUrlDecoder().decode(nonce);
            if (in.length <= IV_BYTES) {
                return false;
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, in, 0, IV_BYTES));
            byte[] plaintext = cipher.doFinal(in, IV_BYTES, in.length - IV_BYTES);
            long issuedAt = Long.parseLong(new String(plaintext, StandardCharsets.US_ASCII));
            long now = clock.instant().getEpochSecond();
            return now - issuedAt <= lifetimeSeconds && issuedAt - now <= FORWARD_SKEW_SECONDS;
        } catch (RuntimeException | GeneralSecurityException e) {
            // forged, truncated, or key-mismatched nonce — invalid, client gets a fresh one
            return false;
        }
    }
}
