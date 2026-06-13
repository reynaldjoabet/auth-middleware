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
import java.time.Instant

given CanEqual[CIString, CIString] = CanEqual.derived
given CanEqual[Scheme, Scheme] = CanEqual.derived
given CanEqual[Method, Method] = CanEqual.derived
given CanEqual[Path, Path] = CanEqual.derived

type HttpsUriNoFragment =
  Match["^https://[^#\\s]+$"]

type NonBlank =
  Not[Blank] & Trimmed

type ClientIdentifier =
  Match["^[A-Za-z0-9._~:/-]{1,128}$"]

type Base64UrlNoPadding =
  Match["^[A-Za-z0-9_-]+$"]

type JwtCompact =
  Match["^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$"]

type PkceS256Challenge =
  Match["^[A-Za-z0-9_-]{43}$"]

type OAuthState =
  Match["^[\\x21\\x23-\\x5B\\x5D-\\x7E]{16,2048}$"]

type OidcNonce =
  Match["^[A-Za-z0-9._~-]{16,64}$"]

type Jti =
  Match["^[A-Za-z0-9._~-]{16,256}$"]

type PositiveMinorUnits =
  GreaterEqual[0]

type ParExpiresInSeconds =
  Interval.Closed[1, 599]

type AuthorizationCodeLifetimeSeconds =
  Interval.Closed[1, 60]

type NonEmptyList[A] =
  List[A] :| MinLength[1]

type NonEmptySet[A] =
  Set[A] :| MinLength[1]

type Issuer = Issuer.T
object Issuer extends RefinedType[String, HttpsUriNoFragment]

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
object RedirectUri extends RefinedType[String, HttpsUriNoFragment]

type ClientId = ClientId.T
object ClientId extends RefinedType[String, ClientIdentifier]

type Subject = Subject.T
object Subject extends RefinedType[String, NonBlank]

type ScopeToken = ScopeToken.T
object ScopeToken
    extends RefinedType[String, Match["^[A-Za-z0-9._~:/-]{1,128}$"]]

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
object JwtId extends RefinedType[String, Jti]

type JwkThumbprint = JwkThumbprint.T
object JwkThumbprint extends RefinedType[String, Base64UrlNoPadding]

type CertificateThumbprint = CertificateThumbprint.T
object CertificateThumbprint extends RefinedType[String, Base64UrlNoPadding]

type RequestUri = RequestUri.T

object RequestUri extends RefinedType[String, NonBlank]

enum GrantType {
  case AuthorizationCode
  case ClientCredentials
  case RefreshToken
  case Ciba
  case TokenExchange
}

enum ResponseType {
  case Code
}

enum CodeChallengeMethod {
  case S256
}

enum ClientKind {
  case Confidential
}

enum ClientAuthenticationMethod {
  case PrivateKeyJwt
  case TlsClientAuth
  case SelfSignedTlsClientAuth
}

enum SenderConstrainedMethod {
  case MTls
  case DPoP
}

enum TokenEndpointAuthSigningAlg {
  case PS256
  case ES256
  case EdDSA
}

enum AccessTokenFormat {
  case Opaque
  case Jwt
}

enum TokenUse {
  case AccessToken
  case RefreshToken
  case IdToken
  case ClientAssertion
  case RequestObject
  case DpopProof
  case JarmResponse
}

final case class RegisteredRedirectUris(
    values: NonEmptySet[RedirectUri]
)

final case class OAuthClient(
    clientId: ClientId,
    kind: ClientKind,
    redirectUris: RegisteredRedirectUris,
    jwksUri: JwksUri,
    authMethod: ClientAuthenticationMethod,
    senderConstrainedMethods: NonEmptySet[SenderConstrainedMethod],
    allowedGrantTypes: NonEmptySet[GrantType],
    allowedScopes: Set[OAuthScope],
    requirePar: Boolean,
    requirePkceS256: Boolean,
    requireSignedRequestObject: Boolean,
    requireJarm: Boolean
)

final case class OAuthAuthorizationServerMetadata(
    issuer: Issuer,
    authorizationEndpoint: AuthorizationEndpoint,
    tokenEndpoint: TokenEndpoint,
    pushedAuthorizationRequestEndpoint: PushedAuthorizationRequestEndpoint,
    jwksUri: JwksUri,
    codeChallengeMethodsSupported: Set[CodeChallengeMethod],
    grantTypesSupported: Set[GrantType],
    responseTypesSupported: Set[ResponseType],
    tokenEndpointAuthMethodsSupported: Set[ClientAuthenticationMethod],
    tokenEndpointAuthSigningAlgsSupported: Set[TokenEndpointAuthSigningAlg],
    dpopSigningAlgValuesSupported: Set[TokenEndpointAuthSigningAlg],
    mtlsEndpointAliases: Option[MtlsEndpointAliases]
)

final case class MtlsEndpointAliases(
    tokenEndpoint: TokenEndpoint,
    pushedAuthorizationRequestEndpoint: Option[
      PushedAuthorizationRequestEndpoint
    ]
)

final case class PushedAuthorizationRequest(
    clientId: ClientId,
    responseType: ResponseType.Code.type,
    redirectUri: RedirectUri,
    scope: NonEmptySet[OAuthScope],
    state: State,
    nonce: Option[Nonce],
    codeChallenge: PkceChallenge,
    codeChallengeMethod: CodeChallengeMethod.S256.type,
    authorizationDetails: Option[NonEmptyList[AuthorizationDetail]],
    signedRequestObject: Option[SignedJwt],
    dpopJkt: Option[JwkThumbprint]
)

final case class PushedAuthorizationResponse(
    requestUri: RequestUri,
    expiresInSeconds: Int :| ParExpiresInSeconds
)

final case class AuthorizationRequestReference(
    clientId: ClientId,
    requestUri: RequestUri
)

final case class AuthorizationResponse(
    code: AuthorizationCode,
    state: State,
    iss: Issuer
)

final case class AuthorizationCodeTokenRequest(
    clientId: ClientId,
    code: AuthorizationCode,
    redirectUri: RedirectUri,
    codeVerifier: PkceVerifier,
    clientAuthentication: ClientAuthentication,
    dpopProof: Option[DpopProofJwt]
)

sealed trait ClientAuthentication

object ClientAuthentication {
  final case class PrivateKeyJwt(
      assertion: SignedJwt
  ) extends ClientAuthentication

  final case class MutualTls(
      certificateThumbprint: CertificateThumbprint
  ) extends ClientAuthentication
}

type DpopProofJwt = DpopProofJwt.T
object DpopProofJwt extends RefinedType[String, JwtCompact]

enum OidcScope {
  case OpenId
  case Profile
  case Email
  case Phone
  case Address
  case OfflineAccess
}

enum OAuthScope {
  case Oidc(value: OidcScope)

  case AccountsRead
  case BalancesRead
  case TransactionsRead
  case BeneficiariesRead
  case DirectDebitsRead
  case StandingOrdersRead
  case ScheduledPaymentsRead

  case PaymentsWrite
  case FundsConfirmationsRead
  case VariableRecurringPaymentsWrite

  case Custom(value: ScopeToken)
}

enum SubjectType {
  case Public
  case Pairwise
}

enum AcrValue {
  case Level1
  case Level2
  case Level3
  case PhishingResistant
  case TransactionSigning
}

enum AmrValue {
  case Password
  case Otp
  case Sms
  case WebAuthn
  case Fido2
  case SmartCard
  case DeviceBinding
  case BankSCA
}

final case class IdTokenClaims(
    iss: Issuer,
    sub: Subject,
    aud: NonEmptySet[ClientId],
    exp: Instant,
    iat: Instant,
    authTime: Option[Instant],
    nonce: Option[Nonce],
    acr: Option[AcrValue],
    amr: Set[AmrValue],
    azp: Option[ClientId],
    cHash: Option[String],
    atHash: Option[String]
)

final case class UserInfoClaims(
    sub: Subject,
    name: Option[String],
    givenName: Option[String],
    familyName: Option[String],
    email: Option[String],
    emailVerified: Option[Boolean],
    phoneNumber: Option[String]
)

final case class OidcProviderMetadata(
    issuer: Issuer,
    authorizationEndpoint: AuthorizationEndpoint,
    tokenEndpoint: TokenEndpoint,
    jwksUri: JwksUri,
    pushedAuthorizationRequestEndpoint: Option[
      PushedAuthorizationRequestEndpoint
    ],
    subjectTypesSupported: Set[SubjectType],
    idTokenSigningAlgValuesSupported: Set[TokenEndpointAuthSigningAlg],
    scopesSupported: Set[OAuthScope],
    claimsSupported: Set[String],
    codeChallengeMethodsSupported: Set[CodeChallengeMethod]
)

enum HttpMethod {
  case GET
  case POST
  case PUT
  case PATCH
  case DELETE
}

final case class ConfirmationClaim(
    method: SenderConstrainedMethod,
    jwkThumbprint: Option[JwkThumbprint],
    certificateThumbprint: Option[CertificateThumbprint]
)

type ResourceAudience = ResourceAudience.T
object ResourceAudience extends RefinedType[String, HttpsUriNoFragment]

final case class DpopProofClaims(
    htm: HttpMethod,
    htu: ResourceAudience,
    iat: Instant,
    jti: JwtId,
    ath: Option[String],
    nonce: Option[String]
)

final case class MtlsClientCertificateBinding(
    subjectDn: String,
    issuerDn: String,
    sha256Thumbprint: CertificateThumbprint,
    notBefore: Instant,
    notAfter: Instant
)

enum RequestObjectMode {
  case None
  case Signed
  case SignedAndEncrypted
}

enum AuthorizationResponseMode {
  case QueryJwt
  case FragmentJwt
  case FormPostJwt
}

final case class JarRequestObject(
    jwt: SignedJwt,
    mode: RequestObjectMode
)

final case class JarmAuthorizationResponse(
    responseJwt: SignedJwt,
    responseMode: AuthorizationResponseMode
)

enum AuthorizationDetail {
  case AccountAccess(
      permissions: NonEmptySet[AccountPermission],
      accountIds: Option[NonEmptySet[AccountId]],
      expiresAt: Option[java.time.Instant]
  )

  case PaymentInitiation(
      paymentType: PaymentType,
      instructedAmount: Money,
      creditor: AccountReference,
      debtor: Option[AccountReference],
      remittanceInformation: Option[RemittanceInformation]
  )

  case FundsConfirmation(
      account: AccountReference,
      amount: Money
  )

}

enum HttpSignatureAlgorithm {
  case RsaPssSha512
  case EcdsaP256Sha256
  case Ed25519
}

enum DigestAlgorithm {
  case Sha256
  case Sha512
}

enum SignatureComponent {
  case Method
  case TargetUri
  case Authority
  case Scheme
  case Path
  case Query
  case Status
  case ContentDigest
  case Authorization
  case DPoP
  case Date
  case XRequestId
  case XFapiInteractionId
}

final case class ContentDigest(
    algorithm: DigestAlgorithm
    // value: ContentDigestValue
)

final case class HttpMessageSignature(
    keyId: String,
    algorithm: HttpSignatureAlgorithm,
    coveredComponents: NonEmptyList[SignatureComponent],
//   signatureInput: SignatureInputValue,
//   signature: SignatureValue,
    created: Instant,
    expires: Option[Instant]
)

final case class SignedResourceRequest[A](
    body: A,
    digest: ContentDigest,
    signature: HttpMessageSignature
)

final case class SignedResourceResponse[A](
    body: A,
    digest: ContentDigest,
    signature: HttpMessageSignature
)

type CurrencyCode = CurrencyCode.T
object CurrencyCode extends RefinedType[String, Match["^[A-Z]{3}$"]]

type MinorUnits = MinorUnits.T
object MinorUnits extends RefinedType[Long, PositiveMinorUnits]

final case class Money(
    currency: CurrencyCode,
    minorUnits: MinorUnits
)

type AccountId = AccountId.T
object AccountId extends RefinedType[String, NonBlank]

type ConsentId = ConsentId.T
object ConsentId extends RefinedType[String, NonBlank]

type PaymentId = PaymentId.T
object PaymentId extends RefinedType[String, NonBlank]

type Iban = Iban.T
object Iban extends RefinedType[String, Match["^[A-Z]{2}[0-9A-Z]{13,32}$"]]

type Bban = Bban.T
object Bban extends RefinedType[String, NonBlank]

type SortCode = SortCode.T
object SortCode extends RefinedType[String, Match["^[0-9]{6}$"]]

type AccountNumber = AccountNumber.T
object AccountNumber extends RefinedType[String, Match["^[0-9]{6,12}$"]]

enum AccountScheme {
  case IBAN
  case BBAN
  case UKSortCodeAccountNumber
  case Proprietary
}

final case class AccountReference(
    scheme: AccountScheme,
    identification: String,
    name: Option[String],
    secondaryIdentification: Option[String]
)

enum AccountPermission {
  case ReadAccountsBasic
  case ReadAccountsDetail
  case ReadBalances
  case ReadBeneficiariesBasic
  case ReadBeneficiariesDetail
  case ReadDirectDebits
  case ReadTransactionsBasic
  case ReadTransactionsDetail
  case ReadStandingOrdersBasic
  case ReadStandingOrdersDetail
  case ReadScheduledPaymentsBasic
  case ReadScheduledPaymentsDetail
}

enum ConsentStatus {
  case AwaitingAuthorization
  case Authorized
  case Rejected
  case Revoked
  case Expired
  case Consumed
}

final case class AccountAccessConsent(
    consentId: ConsentId,
    permissions: NonEmptySet[AccountPermission],
    expirationDateTime: Option[Instant],
    transactionFromDateTime: Option[Instant],
    transactionToDateTime: Option[Instant],
    status: ConsentStatus,
    createdAt: Instant,
    updatedAt: Instant
)

enum PaymentType {
  case DomesticPayment
  case DomesticScheduledPayment
  case DomesticStandingOrder
  case InternationalPayment
  case InternationalScheduledPayment
  case FilePayment
}

type RemittanceInformation = RemittanceInformation.T
object RemittanceInformation
    extends RefinedType[String, Match["^[\\x20-\\x7E]{1,140}$"]]
