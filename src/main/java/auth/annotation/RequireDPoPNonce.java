package auth.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import http.actions.DPoPNonceEnforcementAction;
import play.mvc.With;

/**
 * Requires that a DPoP proof carry a fresh, server-provided nonce (RFC 9449
 * §8-9) on top of {@link RequireDPoP}. A proof that omits it, or presents an
 * unknown / expired / already-used one, is answered with {@code 401},
 * {@code error="use_dpop_nonce"} and a {@code DPoP-Nonce} header the client
 * must echo in the {@code nonce} claim of its next proof.
 *
 * <p>This is the FAPI 2.0 fix for DPoP Proof Replay: without a nonce, a network
 * attacker who reads a leaked resource request (or blocks the honest one) can
 * replay the proof, since per-node jti single-use detection never sees the
 * original. Nonces are stateless encrypted server timestamps (Duende's
 * {@code DefaultDPoPNonceValidator} design, see {@code auth.service.DPoPNonceService})
 * — no store needed, load-balancer safe when nodes share the key. mTLS-bound
 * tokens ({@link RequireMtls}) do not need this — they are not replayable.
 *
 * <pre>
 *   &#64;RequireOAuth2
 *   &#64;RequireDPoP
 *   &#64;RequireDPoPNonce
 *   public Result transfer(Http.Request req) { ... }
 * </pre>
 */
@With(DPoPNonceEnforcementAction.class)
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequireDPoPNonce {
}
