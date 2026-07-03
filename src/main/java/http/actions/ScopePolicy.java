package http.actions;

import java.util.Optional;

import auth.FeatureChecker;
import auth.Principal;
import auth.SecurityAttrs;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * The checks {@link ScopeCheckAction} and {@link AnyScopeCheckAction} share:
 * principal presence, end-user identity, and the feature gate. Scope
 * possession itself stays in each action — that is where ALL and ANY differ.
 */
final class ScopePolicy {

    private ScopePolicy() {}

    static Optional<Principal> principal(Http.Request req) {
        return req.attrs().getOptional(SecurityAttrs.PRINCIPAL);
    }

    static Result noPrincipal(String annotationName) {
        return Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                "Bearer error=\"invalid_token\", error_description=\"No token claims found — "
                        + "@RequireOAuth2 must precede " + annotationName + "\"");
    }

    /** RFC 6750 §3.1 challenge advertising the given scope set. */
    static Result insufficientScope(String advertisedScopes) {
        return Results.forbidden().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                "Bearer error=\"insufficient_scope\", scope=\"" + advertisedScopes + "\"");
    }

    /**
     * The identity and feature checks that run after scope possession has
     * passed; empty means the request may proceed.
     */
    static Optional<Result> checkIdentityAndFeature(
            Principal p, boolean requireUserIdentity, String requiredFeature,
            FeatureChecker features) {

        if (requireUserIdentity && !representsUser(p)) {
            // RFC 9470 §3: the token authenticates a client, not an end user.
            return Optional.of(
                    Results.forbidden().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                            "Bearer error=\"insufficient_user_authentication\", "
                                    + "error_description=\"This operation requires an end-user identity\""));
        }

        if (!requiredFeature.isEmpty() && !features.isEnabled(requiredFeature, p)) {
            // Deliberately unadorned: feature availability is not a token
            // problem, and the gate's name is not the caller's business.
            return Optional.of(Results.forbidden());
        }

        return Optional.empty();
    }

    /**
     * RFC 9068 client-credentials tokens carry no {@code sub}, or one equal to
     * {@code client_id}; only a distinct, non-blank subject counts as a user.
     */
    private static boolean representsUser(Principal p) {
        return p.subject != null && !p.subject.isBlank() && !p.subject.equals(p.clientId);
    }
}
