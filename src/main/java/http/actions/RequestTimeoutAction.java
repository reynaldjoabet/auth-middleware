package http.actions;

// import auth.annotation.RequestTimeout;
// import http.Timeouts;
// import play.mvc.*;

// import java.time.Duration;
// import java.util.concurrent.CompletionStage;

// /**
//  * Bounds the downstream pipeline to the annotation's time budget; on expiry the
//  * client gets 503 + Retry-After while the (uninterrupted) work is abandoned.
//  * Declare outermost to bound the whole pipeline, innermost to bound only the
//  * controller body.
//  */
// public class RequestTimeoutAction extends Action<RequestTimeout> {

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {
//         return Timeouts.within(
//             delegate.call(req),
//             Duration.ofMillis(configuration.millis()),
//             () -> Results.status(Http.Status.SERVICE_UNAVAILABLE)
//                     .withHeader("Retry-After", "1"));
//     }
// }

public class RequestTimeoutAction {
}
