package auth.annotation;

//import play.mvc.With;
import java.lang.annotation.*;

//@With(ResourceIndicatorAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireResource {
    /** The resource server URI that must appear in the token's aud claim */
    String value();
}