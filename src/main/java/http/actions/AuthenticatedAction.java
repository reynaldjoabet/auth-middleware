package http.actions;

import java.util.concurrent.CompletionStage;

import auth.annotation.Authenticated;
import auth.service.TokenAuthenticator;
import jakarta.inject.Inject;
import play.mvc.Action;
import play.mvc.Http;

/**
 * Wired to {@code @Authenticated} — runs the {@link TokenAuthenticator}
 * pipeline with default policy (Bearer or DPoP accepted, no introspection).
 */
public class AuthenticatedAction extends Action<Authenticated> {

    private final TokenAuthenticator authenticator;

    @Inject
    public AuthenticatedAction(TokenAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    public CompletionStage<play.mvc.Result> call(Http.Request req) {
        // The pipeline only adds attrs, so a Request in yields a Request out.
        return authenticator.authenticate(
                req, false, false, rh -> delegate.call((Http.Request) rh));
    }
}
