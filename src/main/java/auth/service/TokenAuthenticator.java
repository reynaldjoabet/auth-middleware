package auth.service;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;

import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;

import auth.MtlsCertificates;
import auth.OAuthAttrs;
import auth.OAuthConfig;
import auth.Principal;
import auth.SecurityAttrs;
import http.SecurityHeaders;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import play.mvc.Http;
import play.mvc.Results;

/**
 * The token-validation pipeline shared by the composed actions
 * ({@code @RequireOAuth2}, {@code @Authenticated}) and the application-wide
 * {@link http.filters.AccessTokenAuthFilter}. Mirrors the structure of
 * Duende's {@code DPoPJwtBearerEvents} and the Scala stack's
 * {@code auth.AccessTokenAuth.middleware}: request hygiene first
 * (MessageReceived), then JWT validation, the cnf binding×scheme dispatch —
 * DPoP proof verification for {@code cnf.jkt}, client-certificate verification
 * for {@code cnf.x5t#S256}, downgrade rejection otherwise — with RFC
 * 6750/9449-compliant {@code WWW-Authenticate} challenges on every rejection
 * path (Challenge). Every challenge carries {@code Cache-Control: no-store}
 * (RFC 6749 §5.1 hygiene).
 *
 * <p>The pipeline is idempotent under composition: if an upstream run (the
 * filter) already authenticated the request, a composed action enforces only
 * its per-route deltas ({@code requireDPoP}, {@code introspect}) against the
 * attrs the first run attached — re-verifying the DPoP proof would spend its
 * {@code jti} a second time and reject the request as its own replay.
 */
@Singleton
public class TokenAuthenticator {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(TokenAuthenticator.class);

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String DPOP_PREFIX = "DPoP ";
    private static final String DPOP_HEADER = "DPoP";
    private static final String DPOP_NONCE_HEADER = "DPoP-Nonce";

    private final OAuthConfig config;
    private final OAuthTokenValidator tokenValidator;
    private final DPoPProofVerifier proofVerifier;
    private final DPoPNonceService nonceService;
    private final TokenIntrospector introspector;

    @Inject
    public TokenAuthenticator(
            OAuthConfig config,
            OAuthTokenValidator tokenValidator,
            DPoPProofVerifier proofVerifier,
            DPoPNonceService nonceService,
            TokenIntrospector introspector) {
        this.config = config;
        this.tokenValidator = tokenValidator;
        this.proofVerifier = proofVerifier;
        this.nonceService = nonceService;
        this.introspector = introspector;
    }

    /**
     * Runs the pipeline and either returns an error {@link play.mvc.Result} or
     * invokes {@code next} with the request enriched by {@link SecurityAttrs}
     * and {@link OAuthAttrs}. Operates on {@link Http.RequestHeader} so both
     * actions and filters can call it; the pipeline only ever adds attrs, so a
     * {@link Http.Request} in yields a {@link Http.Request} out.
     *
     * @param requireDPoP reject plain Bearer presentation (Duende: {@code AllowBearerTokens = false})
     * @param introspect  also check revocation via RFC 7662 (adds a network hop)
     */
    public CompletionStage<play.mvc.Result> authenticate(
            Http.RequestHeader req,
            boolean requireDPoP,
            boolean introspect,
            Function<Http.RequestHeader, CompletionStage<play.mvc.Result>> next) {

        CompletionStage<play.mvc.Result> outcome = doAuthenticate(req, requireDPoP, introspect, next);

        // RFC 9449 §8.2 nonce rotation: when nonces are enforced, every
        // response to a DPoP-scheme request carries a fresh DPoP-Nonce (unless
        // one is already set, e.g. by the use_dpop_nonce challenge). Rotating
        // on success keeps steady state at one round trip per call; rotating
        // on failure hands the client the nonce it needs to recover.
        if (!config.dpopNonceRequired() || !usesDpopScheme(req)) {
            return outcome;
        }
        return outcome.thenApply(result ->
                result.headers().containsKey(DPOP_NONCE_HEADER)
                        ? result
                        : result.withHeader(DPOP_NONCE_HEADER, nonceService.create()));
    }

    private CompletionStage<play.mvc.Result> doAuthenticate(
            Http.RequestHeader req,
            boolean requireDPoP,
            boolean introspect,
            Function<Http.RequestHeader, CompletionStage<play.mvc.Result>> next) {

        // Already authenticated upstream (filter → composed annotation):
        // enforce only the per-route deltas, never a second full run.
        if (req.attrs().getOptional(SecurityAttrs.PRINCIPAL).isPresent()) {
            return enforceDeltas(req, requireDPoP, introspect, next);
        }

        // OAuth 2.1 / RFC 6750 §2.3: query-string tokens leak via logs,
        // referrers and history; reject even with an Authorization header too.
        if (req.queryString().containsKey("access_token")) {
            return completed(challenge(400,
                    "Bearer error=\"invalid_request\", error_description=\"Access tokens must not be sent in the query string\""));
        }

        List<String> authHeaders = req.headers().getAll(Http.HeaderNames.AUTHORIZATION);
        if (authHeaders.size() > 1) {
            return completed(challenge(400,
                    "Bearer error=\"invalid_request\", error_description=\"Multiple Authorization headers\""));
        }
        if (authHeaders.isEmpty()) {
            return completed(challenge(401, (requireDPoP ? "DPoP" : "Bearer") + " realm=\"api\""));
        }

        String auth = authHeaders.get(0);
        // Duende: ProofTokenMaxLength — cap header size before any parsing
        if (auth.length() > config.proofMaxLength()) {
            return completed(challenge(400,
                    "Bearer error=\"invalid_request\", error_description=\"Authorization header exceeds maximum length\""));
        }

        boolean isDPoP = startsWithIgnoreCase(auth, DPOP_PREFIX);
        boolean isBearer = startsWithIgnoreCase(auth, BEARER_PREFIX);
        if (!isDPoP && !isBearer) {
            return completed(challenge(401,
                    "Bearer error=\"invalid_token\", error_description=\"Unsupported token type\""));
        }
        if (requireDPoP && isBearer) {
            return completed(challenge(401,
                    "DPoP error=\"invalid_token\", error_description=\"This endpoint requires DPoP-bound access tokens\""));
        }

        String rawToken = auth.substring((isDPoP ? DPOP_PREFIX : BEARER_PREFIX).length()).trim();

        OAuthTokenValidator.ValidationResult tokenResult = tokenValidator.validate(rawToken);
        if (!tokenResult.valid()) {
            log.debug("Token rejected [{} {}]: {}", req.method(), req.path(), tokenResult.errorDesc());
            return completed(challenge(401, (isDPoP ? "DPoP" : "Bearer")
                    + " error=\"" + tokenResult.errorCode()
                    + "\", error_description=\"" + escape(tokenResult.errorDesc()) + "\""));
        }
        JWTClaimsSet claims = tokenResult.claims();

        // The cnf binding is the source of truth (the AS baked it in), and each
        // binding admits exactly one presentation scheme: cnf.jkt rides DPoP,
        // cnf.x5t#S256 rides Bearer over the bound TLS connection (RFC 8705),
        // unbound rides plain Bearer. Same dispatch as the Scala middleware.
        JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.parse(claims);
        X509CertificateConfirmation cnfX5t = X509CertificateConfirmation.parse(claims);
        if (cnf != null && cnfX5t != null) {
            // Fail closed: a cnf carrying both bindings is malformed, never a
            // free choice of the weaker check.
            return completed(challenge(401, (isDPoP ? "DPoP" : "Bearer")
                    + " error=\"invalid_token\", error_description=\"Malformed confirmation claim\""));
        }

        String dpopJkt = null;
        String mtlsCertSubject = null;
        boolean nonceValid = false;

        if (isDPoP) {
            if (cnf == null) {
                // Covers both the unbound and the mTLS-bound token: neither is
                // legal under the DPoP scheme.
                return completed(challenge(401,
                        "DPoP error=\"invalid_token\", error_description=\"Access token is not DPoP-bound (missing cnf.jkt)\""));
            }

            List<String> proofHeaders = req.headers().getAll(DPOP_HEADER);
            if (proofHeaders.isEmpty()) {
                return completed(challenge(400,
                        "DPoP error=\"invalid_request\", error_description=\"DPoP scheme used but no DPoP header present\""));
            }
            // Duende TokenValidated: exactly one DPoP header, or the request is ambiguous
            if (proofHeaders.size() > 1) {
                return completed(challenge(400,
                        "DPoP error=\"invalid_request\", error_description=\"Multiple DPoP headers found\""));
            }
            String proofHeader = proofHeaders.get(0);
            if (proofHeader.length() > config.proofMaxLength()) {
                return completed(challenge(400,
                        "DPoP error=\"invalid_request\", error_description=\"DPoP proof exceeds maximum length\""));
            }

            String clientId = claims.getClaim("client_id") != null
                    ? claims.getClaim("client_id").toString()
                    : claims.getSubject();

            DPoPProofVerifier.DPoPResult proofResult = proofVerifier.verify(
                    req.method(), requestUri(req), clientId, proofHeader, rawToken, cnf);
            if (!proofResult.valid()) {
                log.info("DPoP proof rejected [{} {}]: {}", req.method(), req.path(), proofResult.errorDesc());
                return completed(challenge(401, "DPoP error=\"" + proofResult.errorCode()
                        + "\", error_description=\"" + escape(proofResult.errorDesc()) + "\""));
            }
            dpopJkt = proofResult.jkt();

            if (proofResult.nonce() != null) {
                nonceValid = nonceService.validate(proofResult.nonce());
                if (!nonceValid) {
                    // Duende: expired/unknown nonce → use_dpop_nonce plus a fresh
                    // DPoP-Nonce the client echoes in its next proof
                    return completed(nonceChallenge("Invalid or expired 'nonce' value."));
                }
            } else if (config.dpopNonceRequired()) {
                // RFC 9449 §8-9: when server nonces are enforced, a proof
                // without one is challenged — the FAPI 2.0 DPoP replay fix.
                return completed(nonceChallenge("Missing 'nonce' value."));
            }
        } else if (cnf != null) {
            // Duende downgrade protection: a cnf-bound token must never work as plain Bearer,
            // otherwise a stolen DPoP token bypasses sender-constraining entirely
            return completed(challenge(401,
                    "Bearer error=\"invalid_token\", error_description=\"Must use DPoP when using an access token with a 'cnf' claim\""));
        } else if (cnfX5t != null) {
            // RFC 8705 §3: a cnf.x5t#S256-bound token is only valid on a
            // connection that presented the matching client certificate.
            // Missing certificate source, missing certificate and thumbprint
            // mismatch all fail closed — never a downgrade to unbound.
            Optional<X509Certificate> clientCert = MtlsCertificates.extract(req);
            if (clientCert.isEmpty()
                    || !MtlsCertificates.matches(clientCert.get(), cnfX5t.getValue().toString())) {
                log.warn("mTLS binding rejected [{} {}]: {}", req.method(), req.path(),
                        clientCert.isEmpty() ? "no client certificate presented" : "thumbprint mismatch");
                return completed(challenge(401,
                        "Bearer error=\"invalid_token\", error_description=\"Client certificate binding failed\""));
            }
            mtlsCertSubject = clientCert.get().getSubjectX500Principal().getName();
        }

        Principal principal;
        try {
            principal = Principal.from(claims);
        } catch (ParseException e) {
            log.debug("Token claims unparsable [{}]: {}", req.path(), e.getMessage());
            return completed(challenge(401,
                    "Bearer error=\"invalid_token\", error_description=\"Malformed token claims\""));
        }

        Http.RequestHeader enriched = req
                .addAttr(SecurityAttrs.PRINCIPAL, principal)
                .addAttr(SecurityAttrs.RAW_TOKEN, rawToken)
                .addAttr(OAuthAttrs.SUBJECT, principal.subject)
                .addAttr(OAuthAttrs.SCOPES, List.copyOf(principal.scopes))
                .addAttr(OAuthAttrs.ISSUER, claims.getIssuer())
                .addAttr(OAuthAttrs.JTI, claims.getJWTID())
                .addAttr(OAuthAttrs.EXPIRES_AT, claims.getExpirationTime().toInstant().getEpochSecond())
                .addAttr(OAuthAttrs.ALL_CLAIMS, claims.getClaims())
                .addAttr(OAuthAttrs.IS_DPOP_BOUND, isDPoP)
                .addAttr(OAuthAttrs.DPOP_NONCE_OK, nonceValid);
        if (principal.clientId != null) {
            enriched = enriched.addAttr(OAuthAttrs.CLIENT_ID, principal.clientId);
        }
        if (dpopJkt != null) {
            enriched = enriched.addAttr(OAuthAttrs.DPOP_JKT, dpopJkt);
        }
        if (mtlsCertSubject != null) {
            enriched = enriched.addAttr(OAuthAttrs.MTLS_CERT_SUBJECT, mtlsCertSubject);
        }

        if (introspect) {
            Http.RequestHeader finalRequest = enriched;
            boolean dpopScheme = isDPoP;
            return introspector
                    .isActiveAsync(rawToken)
                    .thenCompose(active -> {
                        if (!active) {
                            log.warn("Token introspection failed (revoked?): jti={}", claims.getJWTID());
                            return completed(challenge(401, (dpopScheme ? "DPoP" : "Bearer")
                                    + " error=\"invalid_token\", error_description=\"Token has been revoked\""));
                        }
                        return next.apply(finalRequest);
                    });
        }

        return next.apply(enriched);
    }

    /**
     * The stricter per-route flags, checked against the attrs a completed
     * upstream run attached. {@code requireDPoP} reads {@code IS_DPOP_BOUND};
     * {@code introspect} re-checks the raw token against the AS.
     */
    private CompletionStage<play.mvc.Result> enforceDeltas(
            Http.RequestHeader req,
            boolean requireDPoP,
            boolean introspect,
            Function<Http.RequestHeader, CompletionStage<play.mvc.Result>> next) {

        if (requireDPoP && !req.attrs().getOptional(OAuthAttrs.IS_DPOP_BOUND).orElse(false)) {
            return completed(challenge(401,
                    "DPoP error=\"invalid_token\", error_description=\"This endpoint requires DPoP-bound access tokens\""));
        }
        if (introspect) {
            Optional<String> rawToken = req.attrs().getOptional(SecurityAttrs.RAW_TOKEN);
            if (rawToken.isEmpty()) {
                // A principal without its raw token is not a state this pipeline
                // produces; fail closed rather than skip the revocation check.
                return completed(challenge(401,
                        "Bearer error=\"invalid_token\", error_description=\"Token validation failed\""));
            }
            return introspector.isActiveAsync(rawToken.get()).thenCompose(active -> {
                if (!active) {
                    return completed(challenge(401,
                            "Bearer error=\"invalid_token\", error_description=\"Token has been revoked\""));
                }
                return next.apply(req);
            });
        }
        return next.apply(req);
    }

    /** 401 telling the client to retry with a fresh server-issued nonce (RFC 9449 §8). */
    public play.mvc.Result nonceChallenge(String description) {
        return challenge(401,
                "DPoP error=\"use_dpop_nonce\", error_description=\"" + escape(description) + "\"")
                .withHeader(DPOP_NONCE_HEADER, nonceService.create());
    }

    /** RFC 6749 §5.1: every challenge is uncacheable — it may echo token state. */
    private static play.mvc.Result challenge(int status, String wwwAuthenticate) {
        return Results.status(status)
                .withHeader(Http.HeaderNames.WWW_AUTHENTICATE, wwwAuthenticate)
                .withHeader(SecurityHeaders.CACHE_CONTROL, SecurityHeaders.CACHE_CONTROL_NO_STORE)
                .withHeader(SecurityHeaders.PRAGMA, SecurityHeaders.PRAGMA_NO_CACHE);
    }

    private static CompletionStage<play.mvc.Result> completed(play.mvc.Result result) {
        return CompletableFuture.completedFuture(result);
    }

    /** htu = scheme + host + path, no query or fragment — RFC 9449 §4.2. */
    private static URI requestUri(Http.RequestHeader req) {
        return URI.create((req.secure() ? "https" : "http") + "://" + req.host() + req.path());
    }

    private static boolean usesDpopScheme(Http.RequestHeader req) {
        return req.header(Http.HeaderNames.AUTHORIZATION)
                .map(a -> startsWithIgnoreCase(a, DPOP_PREFIX))
                .orElse(false);
    }

    private static boolean startsWithIgnoreCase(String value, String prefix) {
        return value.regionMatches(true, 0, prefix, 0, prefix.length());
    }

    /** Keep validator messages from breaking out of the quoted-string in WWW-Authenticate. */
    private static String escape(String description) {
        return description == null ? "" : description.replace('"', '\'');
    }
}
