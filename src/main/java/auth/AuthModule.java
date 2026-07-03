package auth;

import java.net.URI;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;
import com.typesafe.config.Config;

import auth.service.DPoPNonceService;

/**
 * Guice wiring for the Play (Java) annotation middleware, enabled via
 * {@code play.modules.enabled += "auth.AuthModule"}.
 *
 * <p>Reads the same {@code app.auth.*} configuration tree as the Scala
 * (http4s) stack — issuer/audience/JWKS, DPoP nonce key material, and
 * introspection credentials come from one place ({@code AUTH_ISSUER},
 * {@code DPOP_NONCE_KEY}, {@code AUTH_INTROSPECTION_*}, …), so the two stacks
 * cannot drift.
 */
public class AuthModule extends AbstractModule {

    private static final Logger log = LoggerFactory.getLogger(AuthModule.class);

    @Provides
    @Singleton
    OAuthConfig oauthConfig(Config config) {
        Config auth = config.getConfig("app.auth");
        Config introspection = auth.getConfig("introspection");
        boolean introspectionEnabled = introspection.getBoolean("enabled");

        return new OAuthConfig(
                auth.getString("issuer"),
                auth.getString("audience"),
                URI.create(auth.getString("jwks-uri")),
                OAuthConfig.DEFAULT_CLOCK_SKEW_SECONDS,
                OAuthConfig.DEFAULT_DPOP_CLOCK_SKEW_SECONDS,
                OAuthConfig.DEFAULT_PROOF_MAX_LENGTH,
                auth.getDuration("dpop.nonce.lifetime").toSeconds(),
                introspectionEnabled
                        ? URI.create(introspection.getString("endpoint"))
                        : null,
                introspectionEnabled ? introspection.getString("client-id") : null,
                introspectionEnabled ? introspection.getString("client-secret") : null,
                introspectionEnabled
                        ? (int) introspection.getDuration("request-timeout").toMillis()
                        : OAuthConfig.DEFAULT_INTROSPECTION_TIMEOUT_MILLIS);
    }

    @Provides
    @Singleton
    DPoPNonceService nonceService(Config config, OAuthConfig oauth) {
        Config nonce = config.getConfig("app.auth.dpop.nonce");
        if (!nonce.hasPath("key")) {
            return new DPoPNonceService(oauth); // ephemeral key; logs its own warning
        }
        SecretKey key = decodeKey(nonce.getString("key"));
        List<SecretKey> previousKeys = nonce.getStringList("previous-keys").stream()
                .map(AuthModule::decodeKey)
                .toList();
        return new DPoPNonceService(
                key, previousKeys, oauth.nonceLifetimeSeconds(), Clock.systemUTC());
    }

    /**
     * Fail-closed placeholder: every API key is unknown until the application
     * binds a real store (hash-at-rest, constant-time compare). Overridden by
     * any binding in a later module.
     */
    @Provides
    @Singleton
    ApiKeyStore apiKeyStore() {
        log.warn("No ApiKeyStore bound — @RequireApiKey endpoints will reject "
                + "every key until a real store is provided.");
        return rawKey -> CompletableFuture.completedFuture(Optional.empty());
    }

    private static SecretKey decodeKey(String base64) {
        return DPoPNonceService.keyFromBytes(Base64.getDecoder().decode(base64));
    }
}
