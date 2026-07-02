package http.actions;

// import auth.annotation.Consumes;
// import http.MediaTypes;
// import play.mvc.*;

// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// /**
//  * Rejects requests whose Content-Type is missing or not in the allowed set with
//  * 415, before any body parsing runs. Declare BEFORE body-touching annotations.
//  */
// public class ConsumesAction extends Action<Consumes> {

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {
//         String contentType = req.header(Http.HeaderNames.CONTENT_TYPE).orElse(null);

//         if (!MediaTypes.matches(contentType, configuration.value())) {
//             return CompletableFuture.completedFuture(
//                 Results.status(Http.Status.UNSUPPORTED_MEDIA_TYPE,
//                     "Supported media types: " + String.join(", ", configuration.value())));
//         }
//         return delegate.call(req);
//     }
// }

public class ConsumesAction {
}
