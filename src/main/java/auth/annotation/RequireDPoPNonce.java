package auth.annotation;

// import auth.RequireDPoPNonceAction;
// import play.mvc.With;
import java.lang.annotation.*;

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
 * original. Back it with a nonce store — the Scala {@code auth.DpopNonceStore}
 * port (in-memory, or a shared store behind a load balancer). mTLS-bound tokens
 * ({@link RequireMtls}) do not need this — they are not
 * replayable.
 *
 * <pre>
 *   &#64;RequireOAuth2
 *   &#64;RequireDPoP
 *   &#64;RequireDPoPNonce
 *   public Result transfer(Http.Request req) { ... }
 * </pre>
 */
// @With(RequireDPoPNonceAction.class)
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireDPoPNonce {
}
