package auth

import java.net.URI
import scala.concurrent.duration.*
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm}

/** Configuration for JWT access-token validation.
  *
  * Defaults are deliberately strict, as appropriate for a fintech API:
  *   - only asymmetric signature algorithms are accepted (no HMAC, and
  *     `alg: none` is structurally impossible because only signed JWTs are
  *     parsed)
  *   - issuer and audience are always verified exactly
  *   - `sub`, `exp` and `iat` are required claims
  *
  * @param issuer
  *   expected `iss` claim, matched exactly (e.g. `https://auth.example.com`)
  * @param audience
  *   identifier of this API; the token's `aud` list must contain it
  * @param jwksUri
  *   HTTPS URL of the authorization server's JWK set
  * @param allowedAlgorithms
  *   permitted JWS algorithms; keep this to the algorithms your authorization
  *   server actually uses
  * @param acceptedTokenTypes
  *   permitted JOSE `typ` header values. RFC 9068 access tokens use `at+jwt`;
  *   plain `JWT` (or an absent `typ`) is accepted by default for compatibility.
  *   Restrict to `at+jwt` only if your issuer supports it, to rule out ID-token
  *   replay at the API.
  * @param clockSkew
  *   tolerated clock difference when checking `exp` / `nbf` / `iat`
  * @param requiredClaims
  *   claims that must be present for the token to be accepted
  * @param requireTokenId
  *   if true, tokens without a `jti` claim are rejected; enable this when using
  *   a revocation denylist
  * @param maxTokenLength
  *   hard upper bound on the compact JWT length, to bound parsing work
  * @param jwksCacheTtl
  *   how long fetched JWKS documents are cached
  * @param jwksRefreshTimeout
  *   how long a cache refresh may take before the cached set is reused
  * @param jwksOutageTtl
  *   how long previously fetched (public) keys may continue to be used if the
  *   JWKS endpoint is down; after this, validation fails closed
  * @param httpConnectTimeout
  *   connect timeout for JWKS retrieval
  * @param httpReadTimeout
  *   read timeout for JWKS retrieval
  * @param jwksSizeLimitBytes
  *   maximum accepted size of the JWKS document
  */
final case class AuthConfig(
    issuer: String,
    audience: String,
    jwksUri: URI,
    allowedAlgorithms: Set[JWSAlgorithm] =
      Set(JWSAlgorithm.RS256, JWSAlgorithm.PS256, JWSAlgorithm.ES256),
    acceptedTokenTypes: Set[JOSEObjectType] =
      Set(new JOSEObjectType("at+jwt"), JOSEObjectType.JWT),
    clockSkew: FiniteDuration = 30.seconds,
    requiredClaims: Set[String] = Set("sub", "exp", "iat"),
    requireTokenId: Boolean = false,
    maxTokenLength: Int = 8192,
    jwksCacheTtl: FiniteDuration = 15.minutes,
    jwksRefreshTimeout: FiniteDuration = 15.seconds,
    jwksOutageTtl: FiniteDuration = 6.hours,
    httpConnectTimeout: FiniteDuration = 2.seconds,
    httpReadTimeout: FiniteDuration = 2.seconds,
    jwksSizeLimitBytes: Int = 100 * 1024
) {
  require(issuer.nonEmpty, "issuer must not be empty")
  require(audience.nonEmpty, "audience must not be empty")
  require(
    Option(jwksUri.getScheme).exists(_.equalsIgnoreCase("https")),
    "jwksUri must be an https URL (verification keys must not be fetched over plaintext)"
  )
  require(
    allowedAlgorithms.nonEmpty,
    "at least one JWS algorithm must be allowed"
  )
  require(
    !allowedAlgorithms.exists(JWSAlgorithm.Family.HMAC_SHA.contains),
    "HMAC algorithms are not supported with a JWKS-based verifier; use asymmetric algorithms"
  )
  require(maxTokenLength > 0, "maxTokenLength must be positive")
}
