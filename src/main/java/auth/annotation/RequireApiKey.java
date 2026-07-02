package auth.annotation;

//import play.mvc.With;
import java.lang.annotation.*;

/**
 * Validates an API key from the X-Api-Key header or ?api_key= query param.
 *
 *   @RequireApiKey
 *   public Result data(Http.Request req) { ... }
 *
 *   @RequireApiKey(permissions = {"read:data", "export:data"})
 *   public Result export(Http.Request req) { ... }
 */
//@With(ApiKeyAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireApiKey {
    String[] permissions() default {};
}