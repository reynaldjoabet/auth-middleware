package bench

import java.net.URI
import java.util.{Date, UUID}
import java.util.concurrent.TimeUnit

import cats.effect.unsafe.implicits.global
import cats.effect.IO

import auth.{AuthContext, AuthError, AuthEvents}
import auth.accesstoken.{AccessTokenConfig, AccessTokenValidator}
import auth.revocation.TokenDenylist
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, JWSHeader, JWSSigner}
import com.nimbusds.jose.crypto.{ECDSASigner, RSASSASigner}
import com.nimbusds.jose.jwk.{Curve, JWK, JWKSet}
import com.nimbusds.jose.jwk.gen.{ECKeyGenerator, RSAKeyGenerator}
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import org.openjdk.jmh.annotations.*

/**
  * Cost of one access-token validation on a single thread, with the verified-token cache off (every
  * request pays the signature check) and on (a client reusing its token).
  *
  * The per-core numbers set how many cores the fleet needs: required cores ≈ target req/s ÷ ops/s
  * here, before HTTP and everything else.
  */
@State(Scope.Benchmark)
@BenchmarkMode(Array(Mode.Throughput))
@OutputTimeUnit(TimeUnit.SECONDS)
class ValidationBench {

  @Param(Array("RS256", "ES256"))
  var alg: String = scala.compiletime.uninitialized

  private var token: String                      = scala.compiletime.uninitialized
  private var uncached: AccessTokenValidator[IO] = scala.compiletime.uninitialized
  private var cached: AccessTokenValidator[IO]   = scala.compiletime.uninitialized

  @Setup
  def setup(): Unit = {
    val keyMaterial: (JWK, JWSSigner, JWSAlgorithm) = alg match {
      case "ES256" =>
        val k = new ECKeyGenerator(Curve.P_256).keyID("k").generate()
        (k.toPublicJWK, new ECDSASigner(k), JWSAlgorithm.ES256)
      case _ =>
        val k = new RSAKeyGenerator(2048).keyID("k").generate()
        (k.toPublicJWK, new RSASSASigner(k), JWSAlgorithm.RS256)
    }
    val (jwk, signer, jwsAlg) = keyMaterial
    val now                   = System.currentTimeMillis()
    val claims                = new JWTClaimsSet.Builder()
      .issuer("https://as.bench")
      .audience("https://api.bench")
      .subject("user-1")
      .claim("client_id", "bench")
      .claim("scope", "accounts:read")
      .jwtID(UUID.randomUUID().toString)
      .issueTime(new Date(now))
      .expirationTime(new Date(now + 3_600_000L))
      .build()
    val jwt = new SignedJWT(
      new JWSHeader.Builder(jwsAlg).keyID("k").`type`(new JOSEObjectType("at+jwt")).build(),
      claims
    )
    jwt.sign(signer)
    token = jwt.serialize()

    val keys   = new ImmutableJWKSet[SecurityContext](new JWKSet(jwk))
    val config = AccessTokenConfig(
      "https://as.bench",
      "https://api.bench",
      URI.create("https://as.bench/jwks")
    )
    def build(cfg: AccessTokenConfig) =
      AccessTokenValidator.withKeySource[IO](cfg, keys, AuthEvents.noop[IO], TokenDenylist.none[IO])
    uncached = build(config.copy(verifiedTokenCacheMaxEntries = 0L))
    cached = build(config)
  }

  @Benchmark
  def verifyEveryTime(): Either[AuthError, AuthContext] = uncached.validate(token).unsafeRunSync()

  @Benchmark
  def verifiedTokenCacheHit(): Either[AuthError, AuthContext] =
    cached.validate(token).unsafeRunSync()

}
