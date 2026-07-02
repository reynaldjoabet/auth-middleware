package auth.annotation;

//import auth.AuthenticatedAction;
//import play.mvc.With;
import java.lang.annotation.*;

//@With(AuthenticatedAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface Authenticated {}
