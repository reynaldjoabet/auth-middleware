package http.actions;

// import jakarta.inject.Inject;
// import play.libs.typedmap.TypedKey;
// import play.mvc.*;

// import java.util.Arrays;
// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// public class ApiKeyAction extends Action<RequireApiKey> {

//     public static final TypedKey<ApiKeyPrincipal> PRINCIPAL = TypedKey.create("apikey.principal");

//     private final ApiKeyStore keyStore;  // DB/cache lookup

//     @Inject
//     public ApiKeyAction(ApiKeyStore keyStore) {
//         this.keyStore = keyStore;
//     }

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {

//         // Extract from header or query param
//         String rawKey = req.header("X-Api-Key")
//             .orElseGet(() -> req.getQueryString("api_key") != null
//                 ? req.getQueryString("api_key") : null);

//         if (rawKey == null) {
//             return error("401", "Missing API key");
//         }

//         // Lookup + validate (async DB/cache call)
//         return keyStore.lookup(rawKey)
//             .thenCompose(keyOpt -> {
//                 if (keyOpt.isEmpty()) {
//                     return error("401", "Invalid API key");
//                 }

//                 ApiKeyPrincipal principal = keyOpt.get();

//                 if (!principal.isActive()) {
//                     return error("401", "API key has been revoked");
//                 }

//                 // Check required permissions
//                 if (configuration.permissions().length > 0) {
//                     var required = Arrays.asList(configuration.permissions());
//                     if (!principal.getPermissions().containsAll(required)) {
//                         return error("403", "Insufficient API key permissions: " + required);
//                     }
//                 }

//                 return delegate.call(req.addAttr(PRINCIPAL, principal));
//             });
//     }

//     private CompletionStage<Result> error(String status, String msg) {
//         return CompletableFuture.completedFuture(
//             "401".equals(status)
//                 ? Results.unauthorized("{\"error\":\"" + msg + "\"}")
//                 : Results.forbidden("{\"error\":\"" + msg + "\"}"));
//     }
// }


public class ApiKeyAction {
}