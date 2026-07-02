package http.actions;


// import play.mvc.*;
// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// /**
//  * Enforces that the request used a DPoP-bound token.
//  * Shorthand for @RequireOAuth2(requireDPoP = true) on individual methods.
//  */
// public class DPoPEnforcementAction extends Action<RequireDPoP> {

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {

//         Boolean isDPoP = req.attrs().getOptional(OAuthAttrs.IS_DPOP_BOUND).orElse(false);

//         if (!isDPoP) {
//             return CompletableFuture.completedFuture(
//                 Results.unauthorized()
//                     .withHeader("WWW-Authenticate",
//                         "DPoP realm=\"api\", error=\"invalid_token\", " +
//                         "error_description=\"This endpoint requires a DPoP-bound access token\""));
//         }

//         return delegate.call(req);
//     }
// }

public class DPoPEnforcementAction {
}