package auth.annotation;

import http.actions.DPoPEnforcementAction;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import play.mvc.With;

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
 * <p>Per-endpoint shorthand for {@code @RequireOAuth2(requireDPoP = true)};
 * must be composed after {@link RequireOAuth2} / {@link Authenticated}, which
 * do the actual proof verification.
 *
 * <pre>
 *   &#64;RequireOAuth2
 *   &#64;RequireDPoP
 *   public Result transfer(Http.Request req) { ... }
 * </pre>
 */
@With(DPoPEnforcementAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireDPoP {
}
