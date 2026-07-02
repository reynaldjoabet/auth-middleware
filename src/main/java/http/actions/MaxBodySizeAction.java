package http.actions;

// import auth.annotation.MaxBodySize;
// import http.BodyLimits;
// import play.mvc.*;

// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// /**
//  * Rejects bodies whose declared Content-Length exceeds the annotation's limit
//  * with 413 before reading a byte. Chunked/undeclared bodies (UNKNOWN verdict)
//  * pass through here and must be bounded by the body parser's max length
//  * (play.http.parser.maxMemoryBuffer / maxDiskBuffer or @BodyParser.Of).
//  */
// public class MaxBodySizeAction extends Action<MaxBodySize> {

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {
//         String contentLength = req.header(Http.HeaderNames.CONTENT_LENGTH).orElse(null);

//         if (BodyLimits.checkDeclaredLength(contentLength, configuration.value())
//                 == BodyLimits.Verdict.EXCEEDS_LIMIT) {
//             return CompletableFuture.completedFuture(
//                 Results.status(Http.Status.REQUEST_ENTITY_TOO_LARGE,
//                     "Request body must not exceed " + configuration.value() + " bytes"));
//         }
//         return delegate.call(req);
//     }
// }

public class MaxBodySizeAction {
}
