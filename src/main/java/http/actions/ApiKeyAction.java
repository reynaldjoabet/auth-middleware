package http.actions;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import auth.ApiKeyPrincipal;
import auth.ApiKeyStore;
import auth.annotation.RequireApiKey;
import jakarta.inject.Inject;
import play.libs.typedmap.TypedKey;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Validates an API key from the {@code X-Api-Key} header against the injected
 * {@link ApiKeyStore}, then checks the key's permissions against the
 * annotation. Header only — query-parameter keys leak into logs and Referers.
 */
public class ApiKeyAction extends Action<RequireApiKey> {

    public static final TypedKey<ApiKeyPrincipal> PRINCIPAL = TypedKey.create("apikey.principal");

    private static final String API_KEY_HEADER = "X-Api-Key";

    private final ApiKeyStore keyStore;

    @Inject
    public ApiKeyAction(ApiKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    public CompletionStage<Result> call(Http.Request req) {

        Optional<String> rawKey = req.header(API_KEY_HEADER);
        if (rawKey.isEmpty()) {
            return unauthorizedResult("Missing API key");
        }

        return keyStore.lookup(rawKey.get()).thenCompose(keyOpt -> {
            if (keyOpt.isEmpty()) {
                return unauthorizedResult("Invalid API key");
            }

            ApiKeyPrincipal principal = keyOpt.get();
            if (!principal.active()) {
                return unauthorizedResult("API key has been revoked");
            }

            List<String> required = Arrays.asList(configuration.permissions());
            if (!principal.permissions().containsAll(required)) {
                return CompletableFuture.completedFuture(
                        Results.forbidden("{\"error\":\"insufficient_permissions\"}")
                                .as("application/json"));
            }

            return delegate.call(req.addAttr(PRINCIPAL, principal));
        });
    }

    private static CompletionStage<Result> unauthorizedResult(String message) {
        return CompletableFuture.completedFuture(
                Results.unauthorized("{\"error\":\"" + message + "\"}").as("application/json"));
    }
}
