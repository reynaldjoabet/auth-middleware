package auth.service;

import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;

import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;

import auth.OAuthAttrs;
import auth.OAuthConfig;
import auth.Principal;
import auth.SecurityAttrs;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import play.mvc.Http;
import play.mvc.Results;

/**
 * The token-validation pipeline shared by the composed actions
 * ({@code @RequireOAuth2}, {@code @Authenticated}). Mirrors the structure of
 * Duende's {@code DPoPJwtBearerEvents}: scheme + length checks first
 * (MessageReceived), then JWT validation, DPoP proof verification and the
 * cnf downgrade protection (TokenValidated), with RFC 6750/9449-compliant
 * {@code WWW-Authenticate} challenges on every rejection path (Challenge).
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
     * Runs the pipeline and either returns an error {@link Result} or invokes
     * {@code next} with the request enriched by {@link SecurityAttrs} and
     * {@link OAuthAttrs}.
     *
     * @param requireDPoP reject plain Bearer presentation (Duende: {@code AllowBearerTokens = false})
     * @param introspect  also check revocation via RFC 7662 (adds a network hop)
     */
        public CompletionStage<play.mvc.Result> authenticate(
            Http.Request req,
            boolean requireDPoP,
            boolean introspect,
            Function<Http.Request, CompletionStage<play.mvc.Result>> next) {

        Optional<String> authHeader = req.header(Http.HeaderNames.AUTHORIZATION);
        if (authHeader.isEmpty()) {
            return completed(challenge(401, (requireDPoP ? "DPoP" : "Bearer") + " realm=\"api\""));
        }

        String auth = authHeader.get();
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

        JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.parse(claims);

        String dpopJkt = null;
        boolean nonceValid = false;

        if (isDPoP) {
            if (cnf == null) {
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
            }
        } else if (cnf != null) {
            // Duende downgrade protection: a cnf-bound token must never work as plain Bearer,
            // otherwise a stolen DPoP token bypasses sender-constraining entirely
            return completed(challenge(401,
                    "Bearer error=\"invalid_token\", error_description=\"Must use DPoP when using an access token with a 'cnf' claim\""));
        }

        Principal principal;
        try {
            principal = Principal.from(claims);
        } catch (ParseException e) {
            log.debug("Token claims unparsable [{}]: {}", req.path(), e.getMessage());
            return completed(challenge(401,
                    "Bearer error=\"invalid_token\", error_description=\"Malformed token claims\""));
        }

        Http.Request enriched = req
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

        if (introspect) {
            Http.Request finalRequest = enriched;
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

    /** 401 telling the client to retry with a fresh server-issued nonce (RFC 9449 §8). */
    public play.mvc.Result nonceChallenge(String description) {
        return Results.unauthorized()
                .withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                        "DPoP error=\"use_dpop_nonce\", error_description=\"" + escape(description) + "\"")
                .withHeader(DPOP_NONCE_HEADER, nonceService.create());
    }

    private static play.mvc.Result challenge(int status, String wwwAuthenticate) {
        return Results.status(status).withHeader(Http.HeaderNames.WWW_AUTHENTICATE, wwwAuthenticate);
    }

    private static CompletionStage<play.mvc.Result> completed(play.mvc.Result result) {
        return CompletableFuture.completedFuture(result);
    }

    /** htu = scheme + host + path, no query or fragment — RFC 9449 §4.2. */
    private static URI requestUri(Http.Request req) {
        return URI.create((req.secure() ? "https" : "http") + "://" + req.host() + req.path());
    }

    private static boolean startsWithIgnoreCase(String value, String prefix) {
        return value.regionMatches(true, 0, prefix, 0, prefix.length());
    }

    /** Keep validator messages from breaking out of the quoted-string in WWW-Authenticate. */
    private static String escape(String description) {
        return description == null ? "" : description.replace('"', '\'');
    }
}
