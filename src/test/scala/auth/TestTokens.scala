package auth

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.net.URI
import java.util.Date
import scala.concurrent.duration.*

object TestTokens {

  val issuer = "https://auth.test.example"
  val audience = "https://api.test.example"

  val config: AuthConfig = AuthConfig(
    issuer = issuer,
    audience = audience,
    jwksUri = URI.create("https://auth.test.example/.well-known/jwks.json")
  )

  val signingKey: RSAKey =
    new RSAKeyGenerator(2048).keyID("test-key-1").generate()
  val rogueKey: RSAKey =
    new RSAKeyGenerator(2048).keyID("test-key-1").generate()

  val keySource: ImmutableJWKSet[SecurityContext] =
    new ImmutableJWKSet[SecurityContext](new JWKSet(signingKey.toPublicJWK))

  def claims(
      sub: String = "user-123",
      iss: String = issuer,
      aud: String = audience,
      scope: Option[String] = Some("accounts:read payments:read"),
      jti: Option[String] = Some("jti-abc"),
      expiresIn: FiniteDuration = 5.minutes
  ): JWTClaimsSet = {
    val now = System.currentTimeMillis()
    val b = new JWTClaimsSet.Builder()
      .issuer(iss)
      .audience(aud)
      .issueTime(new Date(now))
      .expirationTime(new Date(now + expiresIn.toMillis))
      .claim("client_id", "mobile-app")
    Option(sub).foreach(b.subject)
    scope.foreach(b.claim("scope", _))
    jti.foreach(b.jwtID)
    b.build()
  }

  def sign(
      claimsSet: JWTClaimsSet,
      key: RSAKey = signingKey,
      typ: JOSEObjectType = new JOSEObjectType("at+jwt"),
      alg: JWSAlgorithm = JWSAlgorithm.RS256
  ): String = {
    val jwt = new SignedJWT(
      new JWSHeader.Builder(alg).keyID(key.getKeyID).`type`(typ).build(),
      claimsSet
    )
    jwt.sign(new RSASSASigner(key))
    jwt.serialize()
  }

  /** Symmetric token for the algorithm-confusion test. */
  def signHmac(claimsSet: JWTClaimsSet): String = {
    val jwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.HS256)
        .`type`(new JOSEObjectType("at+jwt"))
        .build(),
      claimsSet
    )
    jwt.sign(new MACSigner(new Array[Byte](32)))
    jwt.serialize()
  }

  // ---------------------------------------------------------------- DPoP

  val dpopKey: ECKey =
    new ECKeyGenerator(Curve.P_256).keyID("dpop-1").generate()
  val rogueDpopKey: ECKey =
    new ECKeyGenerator(Curve.P_256).keyID("dpop-1").generate()

  val dpopJkt: String = dpopKey.toPublicJWK.computeThumbprint().toString

  /** Claims with an RFC 9449 `cnf.jkt` binding to [[dpopKey]]. */
  def dpopBoundClaims(
      base: JWTClaimsSet = claims(),
      jkt: String = dpopJkt
  ): JWTClaimsSet =
    new JWTClaimsSet.Builder(base)
      .claim("cnf", java.util.Map.of("jkt", jkt))
      .build()

  /** Claims with an RFC 8705 `cnf.x5t#S256` certificate binding. */
  def mtlsBoundClaims(
      x5tS256: String,
      base: JWTClaimsSet = claims()
  ): JWTClaimsSet =
    new JWTClaimsSet.Builder(base)
      .claim("cnf", java.util.Map.of("x5t#S256", x5tS256))
      .build()

  def dpopProof(
      method: String,
      htu: String,
      accessToken: String,
      key: ECKey = dpopKey,
      jti: String = java.util.UUID.randomUUID().toString,
      iatOffset: FiniteDuration = 0.seconds,
      typ: JOSEObjectType = new JOSEObjectType("dpop+jwt"),
      ath: Option[String] = None
  ): String = {
    val claimsSet = new JWTClaimsSet.Builder()
      .jwtID(jti)
      .claim("htm", method)
      .claim("htu", htu)
      .issueTime(new Date(System.currentTimeMillis() + iatOffset.toMillis))
      .claim("ath", ath.getOrElse(DpopVerifier.accessTokenHash(accessToken)))
      .build()
    val jwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.ES256)
        .`type`(typ)
        .jwk(key.toPublicJWK)
        .build(),
      claimsSet
    )
    jwt.sign(new ECDSASigner(key))
    jwt.serialize()
  }

  // ---------------------------------------------------------------- mTLS

  val clientCertPem: String =
    """-----BEGIN CERTIFICATE-----
      |MIIBiDCCAS+gAwIBAgIUTvVZYFM2Yg0SuUS7EflaEH57UmYwCgYIKoZIzj0EAwIw
      |GjEYMBYGA1UEAwwPY2xpZW50LW9uZS50ZXN0MB4XDTI2MDYxMjA3NTAyNloXDTM2
      |MDYwOTA3NTAyNlowGjEYMBYGA1UEAwwPY2xpZW50LW9uZS50ZXN0MFkwEwYHKoZI
      |zj0CAQYIKoZIzj0DAQcDQgAEu1ZEshgTJ63fDcR2672VSgIA2tQk5pVDmn8ljpCn
      |MgrX3emg/texzDG60di+jOByytRV8g4SJJgiWbmqLa0ecqNTMFEwHQYDVR0OBBYE
      |FFuamPsr0Kk2MqQVMUP6ftDumeiEMB8GA1UdIwQYMBaAFFuamPsr0Kk2MqQVMUP6
      |ftDumeiEMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgO9ulLpSh
      |TLb0eATwIPYfUg2OPIg1vGfOZiZyd4Dn/R0CIC7D5+7TqI2goOpsj3/gNx7GBxe3
      |5LHgI8CJyLMlDyIT
      |-----END CERTIFICATE-----""".stripMargin

  val otherCertPem: String =
    """-----BEGIN CERTIFICATE-----
      |MIIBiDCCAS+gAwIBAgIUFlMtURTeraVUx1/YyroWNiSdmaswCgYIKoZIzj0EAwIw
      |GjEYMBYGA1UEAwwPY2xpZW50LXR3by50ZXN0MB4XDTI2MDYxMjA3NTAyNloXDTM2
      |MDYwOTA3NTAyNlowGjEYMBYGA1UEAwwPY2xpZW50LXR3by50ZXN0MFkwEwYHKoZI
      |zj0CAQYIKoZIzj0DAQcDQgAEeyLIxlx8gtwqIo9gqueNxhKbqWb08IkH7xurcgll
      |M1fjP6XglI6V+z7vgoteQHtI4Q7p9XO+XrrOsgA4tp9vmKNTMFEwHQYDVR0OBBYE
      |FGHcLkRz84kLNVP3aDqxjJaSMYdBMB8GA1UdIwQYMBaAFGHcLkRz84kLNVP3aDqx
      |jJaSMYdBMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgSpTuVa4K
      |O82mHHDxgn4CASXUCHXPAGcVl3FgZbEk5DkCICIrUCb8CUlrSOS/S0XmTqCRV1Vn
      |eFhk5VeTR9anjEiX
      |-----END CERTIFICATE-----""".stripMargin
}
