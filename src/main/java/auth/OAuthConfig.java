package auth;

import java.net.URI;

/**
 * Deployment-wide settings for the OAuth2 resource-server middleware.
 *
 * <p>Per-endpoint policy lives on the annotations ({@code auth.annotation.*});
 * everything here applies to the whole service. The DPoP defaults mirror
 * Duende's {@code AspNetCore.Authentication.JwtBearer} {@code DPoPOptions}.
 *
 * @param issuer                     expected {@code iss} of access tokens
 * @param audience                   this resource server's identifier, matched against {@code aud}
 * @param jwksUri                    the AS's JWKS endpoint for signature keys
 * @param clockSkewSeconds           leeway for access-token {@code exp}/{@code nbf}/{@code iat}
 * @param dpopClockSkewSeconds       acceptance window for the DPoP proof {@code iat};
 *                                   Duende: ProofTokenLifetime (5s) + ProofTokenIssuedAtClockSkew (25s)
 * @param proofMaxLength             maximum Authorization / DPoP header length, enforced before any
 *                                   parsing (Duende: ProofTokenMaxLength, anti resource-exhaustion)
 * @param nonceLifetimeSeconds       how long a server-issued DPoP nonce stays valid
 * @param introspectionEndpoint      RFC 7662 endpoint; null disables {@code introspect = true} support
 * @param introspectionClientId      client id for introspection endpoint authentication
 * @param introspectionClientSecret  client secret for introspection endpoint authentication
 * @param introspectionTimeoutMillis connect/read timeout per introspection call — Nimbus's
 *                                   default is infinite; a stalled AS must fail closed, not hang
 */
public record OAuthConfig(
        String issuer,
        String audience,
        URI jwksUri,
        long clockSkewSeconds,
        long dpopClockSkewSeconds,
        int proofMaxLength,
        long nonceLifetimeSeconds,
        URI introspectionEndpoint,
        String introspectionClientId,
        String introspectionClientSecret,
        int introspectionTimeoutMillis) {

    public static final long DEFAULT_CLOCK_SKEW_SECONDS = 60;
    public static final long DEFAULT_DPOP_CLOCK_SKEW_SECONDS = 30;
    public static final int DEFAULT_PROOF_MAX_LENGTH = 4000;
    public static final long DEFAULT_NONCE_LIFETIME_SECONDS = 300;
    public static final int DEFAULT_INTROSPECTION_TIMEOUT_MILLIS = 2000;

    /** Config with defaults and no introspection support. */
    public static OAuthConfig of(String issuer, String audience, URI jwksUri) {
        return new OAuthConfig(issuer, audience, jwksUri,
                DEFAULT_CLOCK_SKEW_SECONDS, DEFAULT_DPOP_CLOCK_SKEW_SECONDS,
                DEFAULT_PROOF_MAX_LENGTH, DEFAULT_NONCE_LIFETIME_SECONDS,
                null, null, null, DEFAULT_INTROSPECTION_TIMEOUT_MILLIS);
    }
}
