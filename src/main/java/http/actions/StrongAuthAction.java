package http.actions;

import auth.Principal;
import auth.SecurityAttrs;
import auth.annotation.RequireStrongAuth;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Enforces a step-up authentication policy on the token's {@code acr}/{@code amr}
 * claims. On failure emits the RFC 9470 challenge
 * ({@code error="insufficient_user_authentication"} with {@code acr_values} and
 * {@code max_age=0}) so the client can re-run authorization with the required
 * strength. Must be composed after {@code @RequireOAuth2}.
 */
public class StrongAuthAction extends Action<RequireStrongAuth> {

    @Override
    public CompletionStage<Result> call(Http.Request req) {

        Optional<Principal> principal = req.attrs().getOptional(SecurityAttrs.PRINCIPAL);
        if (principal.isEmpty()) {
            return CompletableFuture.completedFuture(
                    Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                            "Bearer error=\"invalid_token\", error_description=\"No token claims found — "
                                    + "@RequireOAuth2 must precede @RequireStrongAuth\""));
        }

        Principal p = principal.get();
        boolean satisfied = configuration.acr().equals(p.acr)
                || Arrays.stream(configuration.amr()).anyMatch(p.amr::contains);

        if (!satisfied) {
            // RFC 9470: tell the client which acr to request; max_age=0 forces fresh auth
            return CompletableFuture.completedFuture(
                    Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                            "Bearer error=\"insufficient_user_authentication\", "
                                    + "error_description=\"Stronger authentication is required\", "
                                    + "acr_values=\"" + configuration.acr() + "\", max_age=\"0\""));
        }

        return delegate.call(req);
    }
}
