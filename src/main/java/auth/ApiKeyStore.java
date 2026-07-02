package auth;

import java.util.Optional;
import java.util.concurrent.CompletionStage;

/**
 * Looks up API keys (DB/cache). Implementations must store only a digest of
 * the key (e.g. SHA-256) and compare in constant time — never the raw value.
 */
public interface ApiKeyStore {

    CompletionStage<Optional<ApiKeyPrincipal>> lookup(String rawKey);
}
