package auth.service;

import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
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
 */
@Singleton
public class TokenIntrospector {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(TokenIntrospector.class);

    private final OAuthConfig config;

    @Inject
    public TokenIntrospector(OAuthConfig config) {
        this.config = config;
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

            HTTPResponse httpResponse = request.toHTTPRequest().send();
            TokenIntrospectionResponse response = TokenIntrospectionResponse.parse(httpResponse);
            return response.indicatesSuccess() && response.toSuccessResponse().isActive();
        } catch (Exception e) {
            log.warn("Token introspection failed; failing closed: {}", e.getMessage());
            return false;
        }
    }
}
