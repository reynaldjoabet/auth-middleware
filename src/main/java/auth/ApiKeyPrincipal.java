package auth;

import java.util.Set;

/** The validated identity behind an API key. */
public record ApiKeyPrincipal(
        String keyId,
        String owner,
        boolean active,
        Set<String> permissions) {
}
