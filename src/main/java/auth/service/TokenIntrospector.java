package auth.service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;

import auth.OAuthConfig;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * RFC 7662 token introspection against the AS — used by
 * {@code @RequireOAuth2(introspect = true)} as a revocation check on top of
 * local JWT validation. Network or configuration failures fail <em>closed</em>:
 * a token we cannot prove active is treated as revoked.
 *
 * <p>Connect/read timeouts are always set (Nimbus's default is <em>infinite</em>
 * — a stalled AS would otherwise pin threads forever), and the blocking call
 * runs on a small dedicated pool via {@link #isActiveAsync} rather than the
 * ForkJoin common pool, so introspection latency cannot starve unrelated
 * parallel work.
 */
@Singleton
public class TokenIntrospector {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(TokenIntrospector.class);

    private final OAuthConfig config;
    private final ExecutorService executor;

    @Inject
    public TokenIntrospector(OAuthConfig config) {
        this.config = config;
        AtomicInteger counter = new AtomicInteger();
        this.executor = Executors.newFixedThreadPool(4, runnable -> {
            Thread thread = new Thread(runnable,
                    "token-introspection-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    /** Runs {@link #isActive} on the dedicated introspection pool. */
    public CompletionStage<Boolean> isActiveAsync(String rawToken) {
        return CompletableFuture.supplyAsync(() -> isActive(rawToken), executor);
    }

    /** Blocking network call — callers must run it off the request thread. */
    public boolean isActive(String rawToken) {
        if (config.introspectionEndpoint() == null) {
            log.error("Introspection requested but no introspection endpoint is configured; failing closed");
            return false;
        }
        try {
            TokenIntrospectionRequest request = new TokenIntrospectionRequest(
                    config.introspectionEndpoint(),
                    new ClientSecretBasic(
                            new ClientID(config.introspectionClientId()),
                            new Secret(config.introspectionClientSecret())),
                    new TypelessAccessToken(rawToken));

            HTTPRequest httpRequest = request.toHTTPRequest();
            httpRequest.setConnectTimeout(config.introspectionTimeoutMillis());
            httpRequest.setReadTimeout(config.introspectionTimeoutMillis());

            HTTPResponse httpResponse = httpRequest.send();
            TokenIntrospectionResponse response = TokenIntrospectionResponse.parse(httpResponse);
            return response.indicatesSuccess() && response.toSuccessResponse().isActive();
        } catch (Exception e) {
            log.warn("Token introspection failed; failing closed: {}", e.getMessage());
            return false;
        }
    }
}
