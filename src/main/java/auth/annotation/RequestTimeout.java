package auth.annotation;

//import http.actions.RequestTimeoutAction;
//import play.mvc.With;
import java.lang.annotation.*;

/**
 * Bounds the time the action pipeline may take before the request is answered
 * with 503, mirroring ASP.NET Core's {@code [RequestTimeout]}.
 *
 * The timeout applies to everything downstream of this annotation, so declare it
 * outermost (before auth annotations) to bound the whole pipeline, or innermost
 * to bound only the controller body.
 *
 * Usage:
 *   @RequestTimeout(millis = 5000)
 *   @RequireOAuth2
 *   public Result report(Http.Request req) { ... }
 */
//@With(RequestTimeoutAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequestTimeout {
    /** Maximum time budget for the downstream pipeline, in milliseconds. */
    long millis();
}
