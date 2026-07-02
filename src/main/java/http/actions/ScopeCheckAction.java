package http.actions;

import auth.Principal;
import auth.SecurityAttrs;
import auth.annotation.RequireScope;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Verifies that the token contains ALL required scopes. Reads the principal
 * set by the token pipeline upstream — must be composed after
 * {@code @RequireOAuth2} / {@code @Authenticated}.
 */
public class ScopeCheckAction extends Action<RequireScope> {

    @Override
    public CompletionStage<Result> call(Http.Request req) {

        Optional<Principal> principal = req.attrs().getOptional(SecurityAttrs.PRINCIPAL);
        if (principal.isEmpty()) {
            return CompletableFuture.completedFuture(
                    Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                            "Bearer error=\"invalid_token\", error_description=\"No token claims found — "
                                    + "@RequireOAuth2 must precede @RequireScope\""));
        }

        List<String> required = Arrays.asList(configuration.value());
        if (!principal.get().scopes.containsAll(required)) {
            // RFC 6750 §3.1: advertise the full required set; don't enumerate what's missing
            return CompletableFuture.completedFuture(
                    Results.forbidden().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                            "Bearer error=\"insufficient_scope\", scope=\""
                                    + String.join(" ", required) + "\""));
        }

        return delegate.call(req);
    }
}
