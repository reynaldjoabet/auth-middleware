package http.filters;

import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;

import org.apache.pekko.stream.Materializer;

import com.typesafe.config.Config;

import auth.service.TokenAuthenticator;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import play.mvc.Filter;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Application-wide OAuth 2.0 access-token authentication — the Play
 * counterpart of the Scala stack's {@code auth.AccessTokenAuth.middleware}.
 * Every request outside {@code exclude-paths} runs the full
 * {@link TokenAuthenticator} pipeline (RFC 6750/9068/9449/8705: scheme +
 * hygiene checks, JWT validation, the cnf binding×scheme dispatch, nonce
 * enforcement and rotation) before it reaches the router; open probes like
 * {@code /health} stay reachable via the exclusion list.
 *
 * <p>Deny-by-default posture: with the filter on, forgetting an annotation
 * can no longer expose a route. Annotation-composed routes keep working —
 * the pipeline recognises a request the filter already authenticated and
 * enforces only the per-route deltas ({@code requireDPoP}, {@code introspect},
 * scopes, acr, …), so nothing runs twice.
 *
 * <p>Configured under {@code app.auth.filter} and enabled via
 * {@code play.filters.enabled += "http.filters.AccessTokenAuthFilter"}:
 *
 * <pre>
 *   app.auth.filter {
 *     enabled       = true            # off → the filter is a no-op passthrough
 *     require-dpop  = false           # true rejects plain Bearer everywhere
 *                                     # (the SenderConstraintPolicy.Required posture)
 *     introspect    = false           # RFC 7662 revocation check per request
 *     exclude-paths = ["/health", "/ready"]   # prefix match
 *   }
 * </pre>
 */
@Singleton
public class AccessTokenAuthFilter extends Filter {

    private final TokenAuthenticator authenticator;
    private final boolean enabled;
    private final boolean requireDPoP;
    private final boolean introspect;
    private final List<String> excludePaths;

    @Inject
    public AccessTokenAuthFilter(Materializer mat, TokenAuthenticator authenticator, Config config) {
        super(mat);
        this.authenticator = authenticator;
        Config filter = config.getConfig("app.auth.filter");
        this.enabled = filter.getBoolean("enabled");
        this.requireDPoP = filter.getBoolean("require-dpop");
        this.introspect = filter.getBoolean("introspect");
        this.excludePaths = filter.getStringList("exclude-paths");
    }

    @Override
    public CompletionStage<Result> apply(
            Function<Http.RequestHeader, CompletionStage<Result>> next,
            Http.RequestHeader req) {
        if (!enabled || excluded(req.path())) {
            return next.apply(req);
        }
        return authenticator.authenticate(req, requireDPoP, introspect, next);
    }

    private boolean excluded(String path) {
        return excludePaths.stream().anyMatch(path::startsWith);
    }
}
