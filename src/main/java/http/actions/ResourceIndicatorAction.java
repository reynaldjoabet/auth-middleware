package http.actions;

// import jakarta.inject.Inject;
// import play.mvc.*;

// import java.util.List;
// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// /**
//  * Validates the audience (aud) claim contains this resource server's URI.
//  * RFC 8707 — Resource Indicators for OAuth 2.0.
//  *
//  * Prevents token audience confusion: a token issued for resource server A
//  * cannot be replayed at resource server B even with identical scopes.
//  *
//  * Usage:
//  *   @RequireOAuth2
//  *   @RequireResource("https://api.myservice.com")
//  *   public Result endpoint(...) { ... }
//  */
// public class ResourceIndicatorAction extends Action<RequireResource> {

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {

//         Map<String, Object> claims = req.attrs().get(OAuthAttrs.ALL_CLAIMS);
//         if (claims == null) {
//             return error("Token claims not found");
//         }

//         String requiredResource = configuration.value();

//         // aud claim can be a String or List<String> per RFC 7519
//         Object aud = claims.get("aud");
//         List<String> audiences = switch (aud) {
//             case String s          -> List.of(s);
//             case List<?> l         -> (List<String>) l;
//             case null              -> List.of();
//             default                -> List.of(aud.toString());
//         };

//         if (!audiences.contains(requiredResource)) {
//             return error("Token audience does not include this resource server: " +
//                 requiredResource + ". Token audiences: " + audiences);
//         }

//         return delegate.call(req);
//     }

//     private CompletionStage<Result> error(String desc) {
//         return CompletableFuture.completedFuture(
//             Results.forbidden()
//                 .withHeader("WWW-Authenticate",
//                     "Bearer error=\"invalid_token\", error_description=\"" + desc + "\""));
//     }
// }

public class ResourceIndicatorAction{}