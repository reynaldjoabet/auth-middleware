package http.actions;

import java.util.concurrent.CompletionStage;

import auth.annotation.RequireOAuth2;
import auth.service.TokenAuthenticator;
import jakarta.inject.Inject;
import play.mvc.Action;
import play.mvc.Http;

/**
 * Core OAuth2 token validation Action, wired to {@code @RequireOAuth2}.
 *
 * <p>Flow (see {@link TokenAuthenticator}):
 * <ol>
 *   <li>Extract token from Authorization header (Bearer or DPoP scheme),
 *       capping header length first</li>
 *   <li>Validate the access token (JWT signature, typ, iss/aud, expiry)</li>
 *   <li>If presented as DPoP → verify the proof (htm/htu/iat/ath/jti/cnf.jkt)
 *       and any server-issued nonce; if presented as Bearer with a cnf claim →
 *       reject (downgrade protection)</li>
 *   <li>Optionally introspect (revocation check, off the request thread)</li>
 *   <li>Attach the verified context as TypedKey attrs and delegate</li>
 * </ol>
 */
public class OAuthTokenAction extends Action<RequireOAuth2> {

    private final TokenAuthenticator authenticator;

    @Inject
    public OAuthTokenAction(TokenAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    public CompletionStage<play.mvc.Result> call(Http.Request req) {
        // The pipeline only adds attrs, so a Request in yields a Request out.
        return authenticator.authenticate(
                req, configuration.requireDPoP(), configuration.introspect(),
                rh -> delegate.call((Http.Request) rh));
    }
}
