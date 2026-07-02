package http.actions;

// import jakarta.inject.Inject;
// import play.mvc.*;

// import java.util.Arrays;
// import java.util.List;
// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// /**
//  * Verifies that the token contains ALL required scopes.
//  * Reads scopes from OAuthAttrs set by OAuthTokenAction upstream.
//  * Must be composed AFTER @RequireOAuth2.
//  */
// public class ScopeCheckAction extends Action<RequireScope> {

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {

//         // Token validation must have run first
//         if (!req.attrs().containsKey(OAuthAttrs.SCOPES)) {
//             return CompletableFuture.completedFuture(
//                 Results.unauthorized("Bearer error=\"invalid_token\", " +
//                     "error_description=\"No token claims found — " +
//                     "@RequireOAuth2 must precede @RequireScope\""));
//         }

//         List<String> tokenScopes    = req.attrs().get(OAuthAttrs.SCOPES);
//         List<String> requiredScopes = Arrays.asList(configuration.value());

//         boolean hasAllScopes = tokenScopes.containsAll(requiredScopes);

//         if (!hasAllScopes) {
//             List<String> missing = requiredScopes.stream()
//                 .filter(s -> !tokenScopes.contains(s))
//                 .toList();

//             return CompletableFuture.completedFuture(
//                 Results.forbidden()
//                     .withHeader("WWW-Authenticate",
//                         "Bearer error=\"insufficient_scope\", " +
//                         "error_description=\"Required scopes: " + missing + "\", " +
//                         "scope=\"" + String.join(" ", requiredScopes) + "\""));
//         }

//         return delegate.call(req);
//     }
// }


public class ScopeCheckAction {
}