package http.actions;

// import auth.Principal;
// import auth.SecurityAttrs;
// import auth.annotation.RateLimited;
// import http.RateLimitRegistry;
// import http.TokenBucketRateLimiter;
// import jakarta.inject.Inject;
// import play.mvc.*;

// import java.util.concurrent.CompletableFuture;
// import java.util.concurrent.CompletionStage;

// /**
//  * Enforces the named rate-limit policy from app.rate-limits (resolved through
//  * RateLimitRegistry, which fails fast on unknown names).
//  *
//  * Keys on the authenticated principal when auth ran upstream, otherwise on the
//  * remote address — so declare @RateLimited AFTER @Authenticated/@RequireOAuth2
//  * for per-client limits, or BEFORE them to also shield the token-validation work
//  * itself (at the cost of IP-keyed limits).
//  */
// public class RateLimitAction extends Action<RateLimited> {

//     private final RateLimitRegistry registry;

//     @Inject
//     public RateLimitAction(RateLimitRegistry registry) {
//         this.registry = registry;
//     }

//     @Override
//     public CompletionStage<Result> call(Http.Request req) {
//         TokenBucketRateLimiter limiter = registry.get(configuration.policy());

//         String key = req.attrs().getOptional(SecurityAttrs.PRINCIPAL)
//                 .map(Principal::subject)
//                 .orElse(req.remoteAddress());

//         if (!limiter.tryAcquire(key)) {
//             return CompletableFuture.completedFuture(
//                 Results.status(Http.Status.TOO_MANY_REQUESTS)
//                     .withHeader("Retry-After",
//                         String.valueOf(limiter.retryAfterSeconds(key))));
//         }
//         return delegate.call(req);
//     }
// }

public class RateLimitAction {
}
