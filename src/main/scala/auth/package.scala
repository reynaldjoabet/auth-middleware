package auth
import org.typelevel.ci.*
import org.http4s.Uri.Scheme
import org.http4s.Method
import org.http4s.Uri.Path
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*
import io.github.iltotore.iron.constraint.string.*
import io.github.iltotore.iron.constraint.numeric.*
import io.github.iltotore.iron.constraint.collection.*

given CanEqual[CIString, CIString] = CanEqual.derived
given CanEqual[Scheme, Scheme] = CanEqual.derived
given CanEqual[Method, Method] = CanEqual.derived
given CanEqual[Path, Path] = CanEqual.derived

// Issuer must reject query AND fragment
type IssuerUri = Match["^https://[^?#\\s]+$"]
// Endpoints + redirect_uri MAY carry a query; must not carry a fragment.
type HttpsUriNoFragment = Match["^https://[^#\\s]+$"]

// DPoP htu has neither query nor fragment (RFC 9449 §4.3).
type HtuUri = Match["^https://[^?#\\s]+$"]

type NonBlank = Not[Blank] & Trimmed // non-blank + trim()

// Client-controlled charset for values YOU mint. For values you RECEIVE
// from third parties, prefer the wider RFC grammars below.

type ClientIdentifier = Match["^[A-Za-z0-9._~:/-]{1,128}$"]
type Base64UrlNoPadding = Match["^[A-Za-z0-9_-]+$"]
// SHA-256 base64url is exactly 43 chars (cnf.jkt, cnf.x5t#S256, ath).
type Base64UrlSha256 = Match["^[A-Za-z0-9_-]{43}$"]

// 3rd group + (signature REQUIRED) — rejects unsecured/alg:none shape.
type JwtCompact = Match["^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"]
// JWE compact (5 segments) for signed-and-encrypted request objects / id tokens.
type JweCompact =
  Match[
    "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"
  ]

type PkceS256Challenge = Match["^[A-Za-z0-9_-]{43}$"]
type PkceVerifierC = Match["^[A-Za-z0-9\\-._~]{43,128}$"]

// Values you MINT — strict entropy/charset is appropriate.
type OAuthState = Match["^[\\x21\\x23-\\x5B\\x5D-\\x7E]{16,2048}$"]
type OidcNonce = Match["^[A-Za-z0-9._~-]{16,64}$"]
// jti is opaque (RFC 7519)Only bound size.
type JwtIdC = NonBlank & MaxLength[256]

type NonNegativeMinorUnits = GreaterEqual[0]
type PositiveMinorUnits = Greater[0]

type ParExpiresInSeconds = Positive

// RFC 9126: request_uri is urn:ietf:params:oauth:request_uri:<ref> (or an https URI).
type RequestUriC =
  Match["^(urn:ietf:params:oauth:request_uri:.+|https://[^#\\s]+)$"]

// optional, but worth validating fintech PII.
type EmailAddressC = Match["^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"]

type NonEmptyList[A] = List[A] :| MinLength[1]
type NonEmptySet[A] = Set[A] :| MinLength[1]

type Issuer = Issuer.T
object Issuer extends RefinedType[String, IssuerUri]

type AuthorizationEndpoint = AuthorizationEndpoint.T
object AuthorizationEndpoint extends RefinedType[String, HttpsUriNoFragment]
type TokenEndpoint = TokenEndpoint.T
object TokenEndpoint extends RefinedType[String, HttpsUriNoFragment]
type PushedAuthorizationRequestEndpoint = PushedAuthorizationRequestEndpoint.T
object PushedAuthorizationRequestEndpoint
    extends RefinedType[String, HttpsUriNoFragment]
type JwksUri = JwksUri.T
object JwksUri extends RefinedType[String, HttpsUriNoFragment]
type RedirectUri = RedirectUri.T
object RedirectUri
    extends RefinedType[
      String,
      HttpsUriNoFragment
    ] // OK: query allowed, fragment forbidden

type ClientId = ClientId.T
object ClientId extends RefinedType[String, ClientIdentifier]
type Subject = Subject.T
object Subject
    extends RefinedType[
      String,
      NonBlank & MaxLength[255]
    ] // ADDED max (OIDC sub ≤ 255)

type ScopeToken = ScopeToken.T
object ScopeToken
    extends RefinedType[String, Match["^[A-Za-z0-9._~:/-]{1,128}$"]]
// use this when PARSING scopes from a token issued elsewhere (RFC 6749 NQCHAR).
type ScopeTokenRfc = ScopeTokenRfc.T
object ScopeTokenRfc
    extends RefinedType[String, Match["^[\\x21\\x23-\\x5B\\x5D-\\x7E]+$"]]

type AuthorizationCode = AuthorizationCode.T
object AuthorizationCode extends RefinedType[String, NonBlank]
type AccessToken = AccessToken.T
object AccessToken extends RefinedType[String, NonBlank]
type RefreshToken = RefreshToken.T
object RefreshToken extends RefinedType[String, NonBlank]

type IdTokenJwt = IdTokenJwt.T
object IdTokenJwt extends RefinedType[String, JwtCompact]
type SignedJwt = SignedJwt.T
object SignedJwt extends RefinedType[String, JwtCompact]
type EncryptedJwt = EncryptedJwt.T // for SignedAndEncrypted mode
object EncryptedJwt extends RefinedType[String, JweCompact]
type DpopProofJwt = DpopProofJwt.T
object DpopProofJwt extends RefinedType[String, JwtCompact]

type PkceVerifier = PkceVerifier.T
object PkceVerifier
    extends RefinedType[String, Match["^[A-Za-z0-9\\-._~]{43,128}$"]]
type PkceChallenge = PkceChallenge.T
object PkceChallenge extends RefinedType[String, PkceS256Challenge]

type State = State.T
object State extends RefinedType[String, OAuthState]
type Nonce = Nonce.T
object Nonce extends RefinedType[String, OidcNonce]
type JwtId = JwtId.T
object JwtId extends RefinedType[String, JwtIdC] // SHA-256 fixed length.

// You mint it → you control the format → total construction from a trusted generator.
type MintedJwtId = MintedJwtId.T
object MintedJwtId
    extends RefinedType[String, Match["^[A-Za-z0-9._~-]{16,256}$"]]

// A peer authored it → accept anything RFC-legal, bound only for DoS safety →
// fallible: .either at the edge, may reject.
type ReceivedJwtId = ReceivedJwtId.T
object ReceivedJwtId extends RefinedType[String, Not[Blank] & MaxLength[256]]

/** acr values; `Other` keeps an unrecognised value representable so policy can
  * reject it explicitly rather than failing to parse the token.
  */
enum Acr2 {
  case Level1, Level2, Level3, PhishingResistant, TransactionSigning
  case Other(value: String)
}

enum Amr {
  case Password, Otp, Sms, WebAuthn, Fido2, SmartCard, DeviceBinding, BankSCA
  case Other(value: String)
}

/** Authentication Context Class Reference (`acr`) as received in a token.
  * Unlike the curated [[com.fintech.auth.types.AcrValue]] enum (which the AS
  * mints into id tokens), the value an RS sees is an opaque, IdP-defined string
  * — often a URN such as `urn:openbanking:psd2:sca` — so it is modelled as a
  * non-blank newtype and compared for equality during step-up.
  */
type Acr = Acr.T
object Acr extends RefinedType[String, NonBlank]

type JwkThumbprint = JwkThumbprint.T
object JwkThumbprint extends RefinedType[String, Base64UrlSha256]
type CertificateThumbprint = CertificateThumbprint.T
object CertificateThumbprint extends RefinedType[String, Base64UrlSha256]
type AccessTokenHash = AccessTokenHash.T // DPoP ath
object AccessTokenHash extends RefinedType[String, Base64UrlSha256]

type RequestUri = RequestUri.T
object RequestUri extends RefinedType[String, RequestUriC]
// RFC 8707 resource indicator.
type ResourceIndicator = ResourceIndicator.T
object ResourceIndicator extends RefinedType[String, HttpsUriNoFragment]

type Htu = Htu.T // distinct from resource indicator
object Htu extends RefinedType[String, HtuUri]

type EmailAddress = EmailAddress.T
object EmailAddress extends RefinedType[String, EmailAddressC]

enum ClientAuthenticationMethod {
  case PrivateKeyJwt, TlsClientAuth, SelfSignedTlsClientAuth
}
enum SenderConstrainedMethod {
  case MTls, DPoP
}

/** One signing-alg set, reused for token-endpoint auth, DPoP proofs and id
  * tokens.
  */
enum FapiSigningAlg {
  case PS256, ES256, EdDSA
}
enum AccessTokenFormat {
  case Opaque, Jwt
}
enum TokenUse {
  case AccessToken, RefreshToken, IdToken, ClientAssertion, RequestObject,
    DpopProof, JarmResponse
}
enum SubjectType {
  case Public, Pairwise
}
enum HttpMethod {
  case GET, POST, PUT, PATCH, DELETE
}

/** RFC 7800 confirmation claim. Two cases mirror Nimbus's two confirmation
  * types, so a token can never carry both bindings or neither.
  */
enum ConfirmationClaim {
  case DPoP(jkt: JwkThumbprint)
  case MutualTls(x5tS256: CertificateThumbprint)
}

type Role = Role.T
object Role extends RefinedType[String, NonBlank]

val user = Role("user")
