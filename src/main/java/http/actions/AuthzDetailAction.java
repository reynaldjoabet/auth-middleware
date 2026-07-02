package http.actions;


// import com.fasterxml.jackson.databind.JsonNode;
// import com.fasterxml.jackson.databind.ObjectMapper;
// import jakarta.inject.Inject;
// import play.mvc.*;

// import java.util.*;
// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// /**
//  * Validates authorization_details claim per RFC 9396 (RAR).
//  * Reads the structured authorization_details from the validated JWT
//  * and checks it matches the required type, actions, and locations.
//  */
// public class AuthzDetailAction extends Action<RequireAuthzDetail> {

//     private final ObjectMapper mapper;

//     @Inject
//     public AuthzDetailAction(ObjectMapper mapper) {
//         this.mapper = mapper;
//     }

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {

//         Map<String, Object> claims = req.attrs().get(OAuthAttrs.ALL_CLAIMS);
//         if (claims == null) {
//             return forbidden("Token claims not present — @RequireOAuth2 must run first");
//         }

//         // authorization_details is a JSON array in the token
//         Object rawDetails = claims.get("authorization_details");
//         if (rawDetails == null) {
//             return forbidden("Token does not contain authorization_details (RFC 9396)");
//         }

//         try {
//             JsonNode detailsArray = mapper.valueToTree(rawDetails);
//             if (!detailsArray.isArray()) {
//                 return forbidden("authorization_details must be a JSON array");
//             }

//             String requiredType     = configuration.type();
//             List<String> reqActions = Arrays.asList(configuration.actions());
//             List<String> reqLocations = Arrays.asList(configuration.locations());

//             // Find a matching authorization_details entry
//             for (JsonNode detail : detailsArray) {
//                 String type = detail.path("type").asText();
//                 if (!requiredType.equals(type)) continue;

//                 // Check required actions
//                 if (!reqActions.isEmpty()) {
//                     List<String> grantedActions = new ArrayList<>();
//                     detail.path("actions").forEach(a -> grantedActions.add(a.asText()));
//                     if (!grantedActions.containsAll(reqActions)) continue;
//                 }

//                 // Check required locations (resource server indicator)
//                 if (!reqLocations.isEmpty()) {
//                     List<String> grantedLocations = new ArrayList<>();
//                     detail.path("locations").forEach(l -> grantedLocations.add(l.asText()));
//                     if (!grantedLocations.containsAll(reqLocations)) continue;
//                 }

//                 // Match found — attach the detail to the request for the controller
//                 Http.Request enriched = req.addAttr(
//                     OAuthAttrs.AUTHZ_DETAIL, detail.toString());
//                 return delegate.call(enriched);
//             }

//             return forbidden("No matching authorization_details entry for type=" +
//                 requiredType + " actions=" + reqActions);

//         } catch (Exception e) {
//             return forbidden("Failed to parse authorization_details: " + e.getMessage());
//         }
//     }

//     private CompletionStage<Result> forbidden(String desc) {
//         return CompletableFuture.completedFuture(
//             Results.forbidden()
//                 .withHeader("WWW-Authenticate",
//                     "Bearer error=\"insufficient_authorization_details\", " +
//                     "error_description=\"" + desc + "\""));
//     }
// }

public class AuthzDetailAction {
}