package http.actions;

// import auth.annotation.NoStore;
// import http.SecurityHeaders;
// import play.mvc.*;

// import java.util.concurrent.CompletionStage;

// /**
//  * Forces Cache-Control: no-store, private (+ Pragma: no-cache) on the response,
//  * per RFC 6749 §5.1. Applied after the delegate so it overrides whatever the
//  * controller set.
//  */
// public class NoStoreAction extends Action<NoStore> {

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {
//         return delegate.call(req).thenApply(result ->
//             result
//                 .withHeader(SecurityHeaders.CACHE_CONTROL, SecurityHeaders.CACHE_CONTROL_NO_STORE)
//                 .withHeader(SecurityHeaders.PRAGMA, SecurityHeaders.PRAGMA_NO_CACHE));
//     }
// }

public class NoStoreAction {
}
