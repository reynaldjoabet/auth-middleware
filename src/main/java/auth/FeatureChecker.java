package auth;

/**
 * Decides whether a named product feature is available to the calling
 * principal. Backs {@code @AllowedScope(requiredFeature = ...)}; consulted
 * only when an annotation actually sets a feature, after the token and scope
 * checks have already passed.
 *
 * <p>Bind a real implementation (settings service, flag provider, entitlement
 * lookup) in the application's module; {@link AuthModule} installs a
 * fail-closed placeholder that denies every feature.
 */
@FunctionalInterface
public interface FeatureChecker {

    boolean isEnabled(String feature, Principal principal);
}
