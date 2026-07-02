package http;


// import jakarta.inject.Inject;
// import jakarta.inject.Singleton;
// import play.Logger;
// import play.mvc.Http;

// import java.time.Instant;
// import java.util.HashMap;
// import java.util.Map;

// /**
//  * Structured security event logging for OAuth2 validation.
//  * Follows RFC 8417 (Security Event Token) principles.
//  *
//  * Produces machine-parseable JSON logs for SIEM integration,
//  * anomaly detection, and audit trails.
//  */
// @Singleton
// public class OAuthSecurityLogger {

//     private static final Logger.ALogger securityLog =
//         Logger.of("security.oauth2");

//     public enum EventType {
//         TOKEN_VALID,
//         TOKEN_INVALID,
//         TOKEN_EXPIRED,
//         TOKEN_REPLAYED,       // jti seen before
//         DPOP_INVALID,
//         DPOP_REPLAYED,        // DPoP jti seen before
//         MTLS_MISMATCH,        // certificate does not match cnf.x5t#S256
//         SCOPE_INSUFFICIENT,
//         AUTHZ_DETAIL_MISSING,
//         RESOURCE_MISMATCH,    // audience does not contain this RS
//         TOKEN_REVOKED,        // introspection returned active=false
//         SUSPICIOUS_ACTIVITY   // multiple failures from same IP/client
//     }

//     @Inject
//     public OAuthSecurityLogger() {}

//     public void log(EventType event, Http.Request req, String detail, Map<String, Object> extra) {
//         Map<String, Object> entry = new HashMap<>();
//         entry.put("event",      event.name());
//         entry.put("timestamp",  Instant.now().toString());
//         entry.put("path",       req.path());
//         entry.put("method",     req.method());
//         entry.put("ip",         req.remoteAddress());
//         entry.put("detail",     detail);
//         entry.put("user_agent", req.header("User-Agent").orElse("unknown"));
//         entry.put("request_id", req.header("X-Request-ID").orElse("none"));

//         // Include token claims if available (no sensitive data)
//         req.attrs().getOptional(OAuthAttrs.SUBJECT)
//             .ifPresent(sub -> entry.put("sub", sub));
//         req.attrs().getOptional(OAuthAttrs.CLIENT_ID)
//             .ifPresent(cid -> entry.put("client_id", cid));
//         req.attrs().getOptional(OAuthAttrs.JTI)
//             .ifPresent(jti -> entry.put("jti", jti));

//         if (extra != null) entry.putAll(extra);

//         // Log as structured JSON for SIEM/ELK/Splunk ingestion
//         if (event == EventType.TOKEN_VALID) {
//             securityLog.info(toJson(entry));
//         } else {
//             securityLog.warn(toJson(entry));
//         }
//     }

//     private String toJson(Map<String, Object> map) {
//         // In production use Jackson ObjectMapper
//         StringBuilder sb = new StringBuilder("{");
//         map.forEach((k, v) -> sb
//             .append("\"").append(k).append("\":\"")
//             .append(v).append("\","));
//         if (sb.charAt(sb.length() - 1) == ',') sb.deleteCharAt(sb.length() - 1);
//         sb.append("}");
//         return sb.toString();
//     }
// }

public class OAuthSecurityLogger{}