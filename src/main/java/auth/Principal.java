package auth;

import com.nimbusds.jwt.JWTClaimsSet;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** The validated security context extracted from a verified access token. */
public final class Principal {

    public final String subject;
    public final String clientId;
    public final Set<String> scopes;
    public final String acr;
    public final Set<String> amr;     // contains "webauthn"/"hwk" for a passkey login
    public final String cnfJkt;       // JWK SHA-256 thumbprint the token is bound to (null = bearer)
    public final JWTClaimsSet raw;

    public Principal(String subject, String clientId, Set<String> scopes,
                     String acr, Set<String> amr, String cnfJkt, JWTClaimsSet raw) {
        this.subject = subject;
        this.clientId = clientId;
        this.scopes = scopes;
        this.acr = acr;
        this.amr = amr;
        this.cnfJkt = cnfJkt;
        this.raw = raw;
    }

    public boolean hasScope(String s) {
        return scopes.contains(s);
    }

    public static Principal from(JWTClaimsSet c) throws ParseException {
        Set<String> scopes = Collections.emptySet();
        String scope = c.getStringClaim("scope");                  // RFC 9068: space-delimited
        if (scope != null && !scope.isBlank()) {
            scopes = Arrays.stream(scope.trim().split("\\s+"))
                           .collect(Collectors.toUnmodifiableSet());
        }

        Set<String> amr = Collections.emptySet();
        List<String> amrList = c.getStringListClaim("amr");
        if (amrList != null) {
            amr = Set.copyOf(amrList);
        }

        String cnfJkt = null;
        Map<String, Object> cnf = c.getJSONObjectClaim("cnf");     // RFC 9449 §6
        if (cnf != null && cnf.get("jkt") != null) {
            cnfJkt = cnf.get("jkt").toString();
        }

        return new Principal(
            c.getSubject(),
            c.getStringClaim("client_id"),
            scopes,
            c.getStringClaim("acr"),
            amr,
            cnfJkt,
            c);
    }
}
