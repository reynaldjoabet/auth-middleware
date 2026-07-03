package auth.service;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
 * <p>Two hardening details, matching the Scala {@code DpopNonceValidator}:
 * <ul>
 *   <li>Every ciphertext is purpose-bound via GCM AAD ({@code auth.dpop.nonce})
 *       — the analogue of Duende's DataProtector purpose string. Ciphertext
 *       minted under the same key for any other use can never verify as a
 *       nonce.</li>
 *   <li>Key rotation is first-class: mint with {@code key}, accept with
 *       {@code key} or any of {@code previousKeys}. Roll a key by moving it to
 *       {@code previousKeys}; in-flight nonces stay valid and the old key can
 *       be dropped one nonce-lifetime later.</li>
 * </ul>
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
    /** Purpose AAD — keep in sync with the Scala {@code DpopNonceValidator.StatelessPurpose}. */
    private static final byte[] PURPOSE = "auth.dpop.nonce".getBytes(StandardCharsets.US_ASCII);

    private final SecretKey key;
    private final List<SecretKey> acceptedKeys;
    private final long lifetimeSeconds;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    @Inject
    public DPoPNonceService(OAuthConfig config) {
        this(ephemeralKey(), List.of(), config.nonceLifetimeSeconds(), Clock.systemUTC());
        log.warn("DPoPNonceService using an ephemeral key — nonces will not validate across "
                + "nodes or restarts. Provide a shared SecretKey in production.");
    }

    /**
     * @param key          current minting key, shared by every node
     * @param previousKeys retired minting keys still accepted during rotation
     */
    public DPoPNonceService(SecretKey key, List<SecretKey> previousKeys,
                            long lifetimeSeconds, Clock clock) {
        this.key = key;
        this.acceptedKeys = concat(key, previousKeys);
        this.lifetimeSeconds = lifetimeSeconds;
        this.clock = clock;
    }

    public DPoPNonceService(SecretKey key, long lifetimeSeconds, Clock clock) {
        this(key, List.of(), lifetimeSeconds, clock);
    }

    private static List<SecretKey> concat(SecretKey key, List<SecretKey> previousKeys) {
        return java.util.stream.Stream
                .concat(java.util.stream.Stream.of(key), previousKeys.stream())
                .toList();
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

    /** Wrap key material from a secret manager (16, 24 or 32 bytes). */
    public static SecretKey keyFromBytes(byte[] bytes) {
        if (!Set.of(16, 24, 32).contains(bytes.length)) {
            throw new IllegalArgumentException(
                    "AES key must be 16, 24 or 32 bytes, got " + bytes.length);
        }
        return new SecretKeySpec(bytes, "AES");
    }

    /** Mints a fresh nonce encoding the current server time. */
    public String create() {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(PURPOSE);
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

    /**
     * True if {@code nonce} was minted for this purpose by us (any node sharing
     * the current or a retired key) and is still fresh.
     */
    public boolean validate(String nonce) {
        try {
            byte[] in = Base64.getUrlDecoder().decode(nonce);
            if (in.length <= IV_BYTES) {
                return false;
            }
            for (SecretKey accepted : acceptedKeys) {
                Long issuedAt = decryptTimestamp(accepted, in);
                if (issuedAt != null) {
                    long now = clock.instant().getEpochSecond();
                    return now - issuedAt <= lifetimeSeconds
                            && issuedAt - now <= FORWARD_SKEW_SECONDS;
                }
            }
            return false;
        } catch (RuntimeException e) {
            // forged or truncated nonce — invalid, client gets a fresh one
            return false;
        }
    }

    private Long decryptTimestamp(SecretKey candidate, byte[] in) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, candidate,
                    new GCMParameterSpec(GCM_TAG_BITS, in, 0, IV_BYTES));
            cipher.updateAAD(PURPOSE);
            byte[] plaintext = cipher.doFinal(in, IV_BYTES, in.length - IV_BYTES);
            return Long.parseLong(new String(plaintext, StandardCharsets.US_ASCII));
        } catch (RuntimeException | GeneralSecurityException e) {
            return null;
        }
    }
}
