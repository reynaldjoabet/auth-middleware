package controllers;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import auth.Principal;
import auth.ScopeConstants;
import auth.SecurityAttrs;
import auth.annotation.Authenticated;
import auth.annotation.RequireAnyScope;
import auth.annotation.RequireDPoP;
import auth.annotation.RequireScope;
import auth.annotation.RequireStrongAuth;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Usage demo for the composed security annotations. The first annotation runs
 * outermost: {@code @Authenticated} validates the token and sets
 * {@code SecurityAttrs.PRINCIPAL}; everything after it reads that state.
 * Scopes are always referenced through {@link ScopeConstants}, never string
 * literals.
 */
public class AccountController extends Controller {

    @Authenticated
    @RequireDPoP
    @RequireScope(ScopeConstants.ACCOUNTS_READ)
    public CompletionStage<Result> balance(Http.Request request) {
        Principal p = request.attrs().get(SecurityAttrs.PRINCIPAL);
        return CompletableFuture.completedFuture(
                ok("Balance for " + p.subject + " (client " + p.clientId + ")"));
    }

    /** Any-of demo: a {@code manage} token satisfies the read endpoint. */
    @Authenticated
    @RequireAnyScope({ScopeConstants.BILLING_INVOICES_READ, ScopeConstants.BILLING_INVOICES_MANAGE})
    public CompletionStage<Result> invoices(Http.Request request) {
        Principal p = request.attrs().get(SecurityAttrs.PRINCIPAL);
        return CompletableFuture.completedFuture(ok("Invoices for " + p.subject));
    }

    @Authenticated
    @RequireDPoP
    @RequireScope(ScopeConstants.PAYMENTS_INITIATIONS_CREATE)
    @RequireStrongAuth(acr = "https://refeds.org/profile/mfa", amr = {"webauthn", "hwk"})
    public CompletionStage<Result> transfer(Http.Request request) {
        Principal p = request.attrs().get(SecurityAttrs.PRINCIPAL);
        return CompletableFuture.completedFuture(ok("Transfer authorized for " + p.subject));
    }
}
