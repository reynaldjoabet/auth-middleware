package http.actions;

import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import auth.FeatureChecker;
import auth.Principal;
import auth.annotation.RequireAnyScope;
import jakarta.inject.Inject;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Enforces {@link RequireAnyScope}: AT LEAST ONE of the listed scopes — the
 * OR counterpart of {@link ScopeCheckAction} — plus the shared end-user
 * identity and feature-gate policy. Reads the principal set by the token
 * pipeline upstream — must be composed after {@code @RequireOAuth2} /
 * {@code @Authenticated}.
 */
public class AnyScopeCheckAction extends Action<RequireAnyScope> {

    private final FeatureChecker features;

    @Inject
    public AnyScopeCheckAction(FeatureChecker features) {
        this.features = features;
    }

    @Override
    public CompletionStage<Result> call(Http.Request req) {

        Optional<Principal> principal = ScopePolicy.principal(req);
        if (principal.isEmpty()) {
            return CompletableFuture.completedFuture(
                    ScopePolicy.noPrincipal("@RequireAnyScope"));
        }
        Principal p = principal.get();

        String[] accepted = configuration.value();
        // An empty list can never match: misconfiguration fails closed.
        if (Arrays.stream(accepted).noneMatch(p::hasScope)) {
            // RFC 6750 §3.1: advertise every acceptable scope; the client may
            // obtain any one of them.
            return CompletableFuture.completedFuture(
                    ScopePolicy.insufficientScope(String.join(" ", accepted)));
        }

        Optional<Result> rejection = ScopePolicy.checkIdentityAndFeature(
                p, configuration.requireUserIdentity(), configuration.requiredFeature(),
                features);
        return rejection
                .<CompletionStage<Result>>map(CompletableFuture::completedFuture)
                .orElseGet(() -> delegate.call(req));
    }
}
