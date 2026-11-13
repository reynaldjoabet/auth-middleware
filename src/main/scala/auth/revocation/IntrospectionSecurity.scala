package auth
package revocation

import java.time.Instant
import java.util.{Date, UUID}

import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*

import auth.accesstoken.TokenVerification
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.{Curve, ECKey, JWK, KeyType, OctetKeyPair, RSAKey}
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.{JWSVerificationKeySelector, SecurityContext}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import com.nimbusds.jwt.proc.{DefaultJWTClaimsVerifier, DefaultJWTProcessor}

/**
  * `private_key_jwt` client authentication at the introspection endpoint: RFC 7523 §2.2, with the
  * tightened audience rules of RFC 10070.
  *
  * The service proves who it is with a short-lived JWT signed by its own private key, so no shared
  * secret exists for the authorization server to store or for a leak to expose. FAPI 2.0 and RFC
  * 9700 §2.5 prefer asymmetric client authentication over client secrets.
  *
  * RFC 10070 closes an audience-injection attack on these assertions. The `aud` claim is the
  * authorization server's issuer identifier as its sole value, never the endpoint URL; and the
  * assertion is explicitly typed `client-authentication+jwt`.
  *
  * @param signingKey
  *   this service's private key (RSA, P-256/384/521 EC, or Ed25519), registered with the
  *   authorization server as the client's public key
  * @param issuer
  *   the authorization server's issuer identifier (RFC 8414), the assertion's sole audience
  * @param lifetime
  *   how long an assertion is valid; each request gets a fresh one with its own `jti`
  */
final case class PrivateKeyJwt(
    signingKey: JWK,
    issuer: String,
    lifetime: FiniteDuration = 60.seconds
) {

  require(signingKey.isPrivate, "private_key_jwt needs a private key")
  require(issuer.nonEmpty, "private_key_jwt needs the authorization server's issuer identifier")
  require(
    lifetime > Duration.Zero && lifetime <= 5.minutes,
    "keep client assertions short-lived (0 < lifetime <= 5 minutes)"
  )

  /**
    * The signing algorithm: the key's own `alg` when it names one, else the strongest common choice
    * for its type (PS256 for RSA, as FAPI 2.0 requires instead of RS256).
    */
  val algorithm: JWSAlgorithm =
    Option(signingKey.getAlgorithm).map(a => JWSAlgorithm.parse(a.getName)).getOrElse {
      signingKey match {
        case ec: ECKey if Curve.P_384.equals(ec.getCurve) => JWSAlgorithm.ES384
        case ec: ECKey if Curve.P_521.equals(ec.getCurve) => JWSAlgorithm.ES512
        case _: ECKey                                     => JWSAlgorithm.ES256
        case _: RSAKey                                    => JWSAlgorithm.PS256
        case _: OctetKeyPair                              => JWSAlgorithm.EdDSA
        case other                                        =>
          throw new IllegalArgumentException(s"no JWS algorithm for a ${other.getKeyType} key")
      }
    }

  require(
    !JWSAlgorithm.Family.HMAC_SHA.contains(algorithm) && !KeyType.OCT.equals(signingKey.getKeyType),
    "private_key_jwt signs with an asymmetric key"
  )

  private val signer = new DefaultJWSSignerFactory().createJWSSigner(signingKey, algorithm)

  /**
    * A fresh assertion for `clientId`: `iss` and `sub` the client, `aud` the issuer identifier
    * alone, a unique `jti`, and `exp` `lifetime` from now.
    */
  def assertion(clientId: String, now: Instant = Instant.now()): String = {
    val claims = new JWTClaimsSet.Builder()
      .issuer(clientId)
      .subject(clientId)
      // A single string, not a one-element array: RFC 10070 makes the issuer
      // identifier the sole audience value.
      .audience(issuer)
      .jwtID(UUID.randomUUID().toString)
      .issueTime(Date.from(now))
      .expirationTime(Date.from(now.plusNanos(lifetime.toNanos)))
      .build()
    val header = new JWSHeader.Builder(algorithm)
      .`type`(PrivateKeyJwt.TokenType)
      .keyID(signingKey.getKeyID)
      .build()
    val jwt = new SignedJWT(header, claims)
    jwt.sign(signer)
    jwt.serialize()
  }

  /**
    * The form fields that authenticate the request (RFC 7523 §2.2).
    */
  def formFields(clientId: String): List[(String, String)] =
    List(
      "client_id"             -> clientId,
      "client_assertion_type" -> PrivateKeyJwt.AssertionType,
      "client_assertion"      -> assertion(clientId)
    )

}

object PrivateKeyJwt {

  val AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  /**
    * RFC 10070 §4: client authentication JWTs are explicitly typed.
    */
  val TokenType = new JOSEObjectType("client-authentication+jwt")

}

/**
  * Signed introspection responses (RFC 9701). The service asks for
  * `application/token-introspection+jwt`, and believes an answer only when the authorization server
  * has signed it, so `active: true` cannot be forged or altered between the two, even by something
  * that can see inside TLS.
  *
  * A response is accepted only when:
  *   - it is a JWT of type `token-introspection+jwt` (RFC 9701 §5), signed with an asymmetric key
  *     from the authorization server's JWK set
  *   - `iss` is the authorization server's issuer identifier
  *   - `aud` names this resource server: its client id, or one of `audiences`
  *   - `iat` is present and recent: no older than `maxAge`, and not in the future beyond the skew
  *   - `token_introspection` is an object with a boolean `active`
  *
  * Anything else is treated as no answer, and the request fails closed.
  *
  * @param issuer
  *   the authorization server's issuer identifier
  * @param audiences
  *   values of `aud` that name this resource server, besides its client id
  * @param keySource
  *   the authorization server's signing keys, usually the same JWK set as for access tokens
  */
final case class JwtIntrospectionResponse(
    issuer: String,
    audiences: Set[String],
    keySource: JWKSource[SecurityContext],
    maxAge: FiniteDuration = 5.minutes,
    clockSkew: FiniteDuration = 30.seconds
) {

  require(issuer.nonEmpty, "a JWT introspection response needs the issuer to expect")

  /**
    * `Some(active)` from a verified response, `None` when the response cannot be trusted.
    */
  def verify(body: String, clientId: String, now: Instant = Instant.now()): Option[Boolean] =
    try {
      val claims = processor(clientId).process(SignedJWT.parse(body.trim), null)
      val iat    = Option(claims.getIssueTime).map(_.toInstant)
      val skew   = java.time.Duration.ofNanos(clockSkew.toNanos)
      val fresh  = iat.exists { at =>
        !at.isAfter(now.plus(skew)) &&
        !at.isBefore(now.minusNanos(maxAge.toNanos).minus(skew))
      }
      val active =
        Option(claims.getJSONObjectClaim("token_introspection"))
          .flatMap(member => Option(member.get("active")))
          .collect { case b: java.lang.Boolean => b.booleanValue }
      if (fresh) active else None
    } catch {
      case _: java.text.ParseException                => None
      case _: com.nimbusds.jose.proc.BadJOSEException => None
      case _: com.nimbusds.jose.JOSEException         => None
    }

  private def processor(clientId: String): DefaultJWTProcessor[SecurityContext] = {
    val p = new DefaultJWTProcessor[SecurityContext]()
    p.setJWSTypeVerifier(TokenVerification.typeVerifier(Set(JwtIntrospectionResponse.TokenType)))
    p.setJWSKeySelector(
      new JWSVerificationKeySelector[SecurityContext](
        JwtIntrospectionResponse.Algorithms.asJava,
        keySource
      )
    )
    p.setJWTClaimsSetVerifier(
      new DefaultJWTClaimsVerifier[SecurityContext](
        (audiences + clientId).asJava,
        new JWTClaimsSet.Builder().issuer(issuer).build(),
        Set("iat", "token_introspection").asJava,
        null
      )
    )
    p
  }

}

object JwtIntrospectionResponse {

  /**
    * RFC 9701 §10.3: the media type of the response, and (without `application/`) its JWT `typ`.
    */
  val MediaType = "application/token-introspection+jwt"

  val TokenType = new JOSEObjectType("token-introspection+jwt")

  // Asymmetric only: the authorization server signs, it does not share a key with us.
  private val Algorithms: Set[JWSAlgorithm] =
    Set(
      JWSAlgorithm.RS256,
      JWSAlgorithm.PS256,
      JWSAlgorithm.PS384,
      JWSAlgorithm.PS512,
      JWSAlgorithm.ES256,
      JWSAlgorithm.ES384,
      JWSAlgorithm.ES512,
      JWSAlgorithm.EdDSA
    )

}
