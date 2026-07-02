package http.actions;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import auth.OAuthAttrs;
import auth.annotation.RequireDPoPNonce;
import auth.service.TokenAuthenticator;
import jakarta.inject.Inject;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Results;

/**
 * Enforces a fresh server-issued nonce in the DPoP proof (RFC 9449 §8).
 * The token pipeline already rejected stale/forged nonces; this action rejects
 * proofs that carried none, answering {@code use_dpop_nonce} plus a
 * {@code DPoP-Nonce} header so the client can retry — Duende's
 * {@code Challenge} behavior. Must be composed after {@code @RequireOAuth2}.
 */
public class DPoPNonceEnforcementAction extends Action<RequireDPoPNonce> {

    private final TokenAuthenticator authenticator;

    @Inject
    public DPoPNonceEnforcementAction(TokenAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    public CompletionStage<play.mvc.Result> call(Http.Request req) {

        if (req.attrs().getOptional(OAuthAttrs.IS_DPOP_BOUND).isEmpty()) {
            return CompletableFuture.completedFuture(
                    Results.unauthorized().withHeader(Http.HeaderNames.WWW_AUTHENTICATE,
                            "Bearer error=\"invalid_token\", error_description=\"No token claims found — "
                                    + "@RequireOAuth2 must precede @RequireDPoPNonce\""));
        }

        boolean nonceOk = req.attrs().getOptional(OAuthAttrs.DPOP_NONCE_OK).orElse(false);
        if (!nonceOk) {
            return CompletableFuture.completedFuture(
                    authenticator.nonceChallenge("Missing 'nonce' value."));
        }

        return delegate.call(req);
    }
}
