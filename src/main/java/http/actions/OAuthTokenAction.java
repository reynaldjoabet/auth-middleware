package http.actions;

// import com.auth0.jwt.interfaces.DecodedJWT;
// import jakarta.inject.Inject;
// import play.Logger;
// import play.mvc.*;

// import java.util.Arrays;
// import java.util.List;
// import java.util.Optional;
// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// /**
//  * Core OAuth2 token validation Action.
//  * Wired to @RequireOAuth2 via @With.
//  *
//  * Flow:
//  *  1. Extract token from Authorization header (Bearer or DPoP scheme)
//  *  2. If DPoP header present → validate DPoP proof first
//  *  3. Validate the access token (JWT signature, claims, binding)
//  *  4. Optionally introspect (for opaque tokens or revocation check)
//  *  5. Attach validated claims to request as TypedKey attrs
//  *  6. delegate.call(enrichedRequest) → controller
//  */
// public class OAuthTokenAction extends Action<RequireOAuth2> {

//     private static final Logger.ALogger log = Logger.of(OAuthTokenAction.class);

//     private final OAuthTokenValidator tokenValidator;
//     private final DPoPProofVerifier  dpopValidator;
//     private final TokenIntrospector   introspector;

//     @Inject
//     public OAuthTokenAction(
//             OAuthTokenValidator tokenValidator,
//             DPoPProofVerifier dpopValidator,
//             TokenIntrospector introspector) {
//         this.tokenValidator = tokenValidator;
//         this.dpopValidator  = dpopValidator;
//         this.introspector   = introspector;
//     }

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {

//         // ── Step 1: Extract Authorization header ─────────────────────────────
//         Optional<String> authHeader = req.header("Authorization");
//         if (authHeader.isEmpty()) {
//             return unauthorized("Bearer realm=\"api\", error=\"invalid_token\", " +
//                                 "error_description=\"Missing Authorization header\"");
//         }

//         String auth = authHeader.get();
//         boolean isDPoP   = auth.startsWith("DPoP ");
//         boolean isBearer = auth.startsWith("Bearer ");

//         if (!isDPoP && !isBearer) {
//             return unauthorized("Bearer realm=\"api\", error=\"invalid_token\", " +
//                                 "error_description=\"Unsupported token type\"");
//         }

//         // ── Step 2: Enforce DPoP-only if annotation requires it ───────────────
//         if (configuration.requireDPoP() && isBearer) {
//             return unauthorized("DPoP realm=\"api\", error=\"invalid_token\", " +
//                                 "error_description=\"This endpoint requires DPoP-bound tokens\"");
//         }

//         String rawToken = auth.substring(isDPoP ? 5 : 7);

//         // ── Step 3: Validate DPoP proof header if present ─────────────────────
//         Optional<String> dpopJkt = Optional.empty();
//         Optional<String> dpopHeader = req.header("DPoP");

//         if (isDPoP) {
//             if (dpopHeader.isEmpty()) {
//                 return badRequest("error=\"invalid_dpop_proof\", " +
//                                   "error_description=\"DPoP scheme used but no DPoP header present\"");
//             }
//             DPoPProofVerifier.DPoPResult dpopResult =
//                 dpopValidator.validate(dpopHeader.get(), req, rawToken);

//             if (!dpopResult.valid()) {
//                 log.warn("DPoP proof rejected [{}]: {}", req.path(), dpopResult.errorDesc());
//                 return unauthorized(
//                     "error=\"" + dpopResult.errorCode() + "\", " +
//                     "error_description=\"" + dpopResult.errorDesc() + "\"");
//             }
//             dpopJkt = Optional.of(dpopResult.jkt());
//         }

//         // ── Step 4: Validate the access token ────────────────────────────────
//         OAuthTokenValidator.ValidationResult tokenResult =
//             tokenValidator.validate(rawToken, dpopJkt);

//         if (!tokenResult.valid()) {
//             log.warn("Token rejected [{}]: {}", req.path(), tokenResult.errorDesc());
//             return unauthorized(
//                 "Bearer error=\"" + tokenResult.errorCode() + "\", " +
//                 "error_description=\"" + tokenResult.errorDesc() + "\"");
//         }

//         DecodedJWT jwt = tokenResult.jwt();

//         // ── Step 5: Optional token introspection (revocation check) ──────────
//         if (configuration.introspect()) {
//             boolean active = introspector.introspect(rawToken);
//             if (!active) {
//                 log.warn("Token introspection failed (revoked?): jti={}", jwt.getId());
//                 return unauthorized("Bearer error=\"invalid_token\", " +
//                                     "error_description=\"Token has been revoked\"");
//             }
//         }

//         // ── Step 6: Extract claims and enrich the request ─────────────────────
//         List<String> scopes = Arrays.asList(
//             jwt.getClaim("scope").asString().split(" "));

//         Http.Request enrichedRequest = req
//             .addAttr(OAuthAttrs.SUBJECT,     jwt.getSubject())
//             .addAttr(OAuthAttrs.CLIENT_ID,   jwt.getClaim("client_id").asString())
//             .addAttr(OAuthAttrs.SCOPES,      scopes)
//             .addAttr(OAuthAttrs.ISSUER,      jwt.getIssuer())
//             .addAttr(OAuthAttrs.JTI,         jwt.getId())
//             .addAttr(OAuthAttrs.EXPIRES_AT,  jwt.getExpiresAtAsInstant().getEpochSecond())
//             .addAttr(OAuthAttrs.IS_DPOP_BOUND, isDPoP);

//         if (dpopJkt.isPresent()) {
//             enrichedRequest = enrichedRequest.addAttr(OAuthAttrs.DPOP_JKT, dpopJkt.get());
//         }

//         log.debug("OAuth2 validated: sub={}, scopes={}, dpop={}", 
//             jwt.getSubject(), scopes, isDPoP);

//         return delegate.call(enrichedRequest);
//     }

//     // ── WWW-Authenticate compliant error responses ────────────────────────────

//     private CompletionStage<Result> unauthorized(String wwwAuth) {
//         return CompletableFuture.completedFuture(
//             Results.unauthorized().withHeader("WWW-Authenticate", wwwAuth));
//     }

//     private CompletionStage<Result> badRequest(String detail) {
//         return CompletableFuture.completedFuture(
//             Results.badRequest("{\"error\":\"invalid_request\",\"error_description\":\"" + detail + "\"}"));
//     }
// }

public class OAuthTokenAction {
}