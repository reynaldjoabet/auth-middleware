package auth.annotation;

//import auth.RequireScopeAction;


//import play.mvc.With;
import java.lang.annotation.*;

//@With(RequireScopeAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireScope {
    String value();
}

// /**
//  * Validates that the token contains ALL the required scopes.
//  * Must be composed with @RequireOAuth2.
//  *
//  * Usage:
//  *   @RequireOAuth2
//  *   @RequireScope({"read:orders", "read:profile"})
//  *   public Result orders(Http.Request req) { ... }
//  */
// @With(ScopeCheckAction.class)
// @Target({ElementType.TYPE, ElementType.METHOD})
// @Retention(RetentionPolicy.RUNTIME)
// public @interface RequireScope {
//     /** All listed scopes must be present in the token */
//     String[] value();
// }