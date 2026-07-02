package http.actions;

import auth.Principal;
import auth.SecurityAttrs;
import auth.annotation.RequireResource;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Validates the audience ({@code aud}) claim contains this resource server's
 * URI (RFC 8707 — Resource Indicators). Must be composed after
 * {@code @RequireOAuth2}.
 */
public class ResourceIndicatorAction extends Action<RequireResource> {

    @Override
    public CompletionStage<Result> call(Http.Request req) {

        Optional<Principal> principal = req.attrs().getOptional(SecurityAttrs.PRINCIPAL);
        if (principal.isEmpty()) {
            return error("No token claims found — @RequireOAuth2 must precede @RequireResource");
        }

        String requiredResource = configuration.value();
        if (!principal.get().raw.getAudience().contains(requiredResource)) {
            // don't echo the token's actual audiences back to the caller
            return error("Token audience does not include this resource server");
        }

        return delegate.call(req);
    }

    private static CompletionStage<Result> error(String desc) {
        return CompletableFuture.completedFuture(
                Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                        "Bearer error=\"invalid_token\", error_description=\"" + desc + "\""));
    }
}
