package auth;

import java.util.List;
import java.util.Map;
import play.libs.typedmap.TypedKey;

/** Request attributes populated by the OAuth2 token pipeline after successful validation. */
public final class OAuthAttrs {

    // Core token claims
    public static final TypedKey<String>       SUBJECT    = TypedKey.create("oauth2.sub");
    public static final TypedKey<String>       CLIENT_ID  = TypedKey.create("oauth2.client_id");
    public static final TypedKey<List<String>> SCOPES     = TypedKey.create("oauth2.scopes");
    public static final TypedKey<String>       ISSUER     = TypedKey.create("oauth2.iss");
    public static final TypedKey<String>       JTI        = TypedKey.create("oauth2.jti");
    public static final TypedKey<Long>         EXPIRES_AT = TypedKey.create("oauth2.exp");
    public static final TypedKey<Map<String, Object>> ALL_CLAIMS = TypedKey.create("oauth2.claims");

    // DPoP (RFC 9449)
    public static final TypedKey<String>  DPOP_JKT      = TypedKey.create("oauth2.dpop_jkt");
    public static final TypedKey<Boolean> IS_DPOP_BOUND = TypedKey.create("oauth2.is_dpop_bound");
    /** True only if the proof carried a nonce we issued and it was still fresh. */
    public static final TypedKey<Boolean> DPOP_NONCE_OK = TypedKey.create("oauth2.dpop_nonce_ok");

    // mTLS (RFC 8705)
    public static final TypedKey<String> MTLS_CERT_SUBJECT = TypedKey.create("oauth2.mtls_cert_subject");

    // RAR (RFC 9396) — the matched authorization_details entry, as JSON
    public static final TypedKey<String> AUTHZ_DETAIL = TypedKey.create("oauth2.authz_detail");

    private OAuthAttrs() {}
}
