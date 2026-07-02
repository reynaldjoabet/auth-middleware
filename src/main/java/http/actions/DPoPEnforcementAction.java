package http.actions;

import auth.OAuthAttrs;
import auth.annotation.RequireDPoP;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Enforces that the request used a DPoP-bound token. Per-endpoint shorthand
 * for {@code @RequireOAuth2(requireDPoP = true)} — the proof itself was
 * already verified by the token pipeline; this only rejects Bearer
 * presentation. Must be composed after {@code @RequireOAuth2}.
 */
public class DPoPEnforcementAction extends Action<RequireDPoP> {

    @Override
    public CompletionStage<Result> call(Http.Request req) {

        Optional<Boolean> isDPoP = req.attrs().getOptional(OAuthAttrs.IS_DPOP_BOUND);
        if (isDPoP.isEmpty()) {
            return CompletableFuture.completedFuture(
                    Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                            "Bearer error=\"invalid_token\", error_description=\"No token claims found — "
                                    + "@RequireOAuth2 must precede @RequireDPoP\""));
        }

        if (!isDPoP.get()) {
            return CompletableFuture.completedFuture(
                    Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                            "DPoP error=\"invalid_token\", "
                                    + "error_description=\"This endpoint requires a DPoP-bound access token\""));
        }

        return delegate.call(req);
    }
}
