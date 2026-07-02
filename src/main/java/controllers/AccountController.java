// package controllers;

// import auth.annotation.Authenticated;
// import auth.Principal;
// import auth.annotation.RequireDPoP;
// import auth.annotation.RequireScope;
// import auth.annotation.RequireStrongAuth;
// import auth.SecurityAttrs;
// import play.mvc.Controller;
// import play.mvc.Http;
// import play.mvc.Result;

// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// public class AccountController extends Controller {

//     // Outermost annotation runs first: Authenticated sets PRINCIPAL, then the rest read it.
//     @Authenticated
//     @RequireDPoP
//     @RequireScope("accounts.read")
//     public CompletionStage<Result> balance(Http.Request request) {
//         Principal p = request.attrs().get(SecurityAttrs.PRINCIPAL);
//         return CompletableFuture.completedFuture(
//             ok("Balance for " + p.subject + " (client " + p.clientId + ")"));
//     }

//     @Authenticated
//     @RequireDPoP
//     @RequireScope("payments.write")
//     @RequireStrongAuth(acr = "https://refeds.org/profile/mfa", amr = {"webauthn", "hwk"})
//     public CompletionStage<Result> transfer(Http.Request request) {
//         Principal p = request.attrs().get(SecurityAttrs.PRINCIPAL);
//         return CompletableFuture.completedFuture(ok("Transfer authorized for " + p.subject));
//     }
// }



public class AccountController{}
