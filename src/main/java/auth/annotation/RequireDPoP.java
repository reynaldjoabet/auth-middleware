package auth.annotation;

// import auth.RequireDPoPAction;
// import play.mvc.With;
import java.lang.annotation.*;

/**
 * Enforces DPoP-only access (RFC 9449) on a controller or action method:
 * the access token must be presented with the {@code DPoP} scheme and a valid
 * proof bound to the token's {@code cnf.jkt} thumbprint.
 *
 * <p>DPoP sender-constraining alone does not stop a network attacker who reads
 * a leaked resource request and replays it (or blocks the honest one so the RS
 * never sees the original): per-node jti single-use detection cannot fire on a
 * request the RS never received. The RS-provided nonce mechanism closes this —
 * see the formal analysis in the README (FAPI 2.0, DPoP Proof Replay). Enforce
 * a nonce via {@link RequireDPoPNonce} on high-value endpoints, or prefer mTLS
 * sender-constraining ({@link RequireMtls}), which is not replayable.
 *
 * <p>Shorthand for {@code @RequireOAuth2(requireDPoP = true)}.
 *
 * <pre>
 *   &#64;RequireOAuth2
 *   &#64;RequireDPoP
 *   public Result transfer(Http.Request req) { ... }
 * </pre>
 */
// @With(RequireDPoPAction.class)
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireDPoP {
}
