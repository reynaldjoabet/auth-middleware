package bench

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.util.{Date, UUID}

import scala.jdk.CollectionConverters.*

import auth.dpop.DpopVerifier
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.{ECDSASigner, RSASSASigner}
import com.nimbusds.jose.jwk.{Curve, ECKey, JWKSet, RSAKey}
import com.nimbusds.jose.jwk.gen.{ECKeyGenerator, RSAKeyGenerator}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}

/**
  * Test material for an end-to-end load test (see `bench/loadtest/run.sh`): an issuer key set, a
  * population of distinct access tokens, and a pool of single-use DPoP proofs.
  *
  * {{{
  *   bench/runMain bench.MintLoadTokens <out-dir> <issuer> <audience> <htu> <tokens> <proofs> [nonces]
  * }}}
  *
  * With a `nonces` file (one server-issued DPoP nonce per line), proof `i` carries nonce `i mod n`:
  * one nonce for stateless nonces, one per proof for single-use (Redis) nonces.
  *
  * Writes `jwks.json`, `tokens.txt` (one bearer token per line; skipped when `tokens` is 0) and
  * `dpop.txt` (one DPoP-bound token, then one proof per line). Proofs expire `proofMaxAge` (60 s)
  * after minting, so mint them right before the DPoP run: the issuer key is kept in
  * `signing-key.json` and reused, so a second run matches the key set the server already loaded.
  */
object MintLoadTokens {

  def main(args: Array[String]): Unit = {
    val Array(outDir, issuer, audience, htu, tokenCount, proofCount) = args.take(6)
    val nonces: Vector[String]                                       =
      args.lift(6).fold(Vector.empty)(f => Files.readAllLines(Paths.get(f)).asScala.toVector)
    val out = Paths.get(outDir)
    Files.createDirectories(out)

    val keyFile            = out.resolve("signing-key.json")
    val signingKey: RSAKey =
      if (Files.exists(keyFile)) RSAKey.parse(Files.readString(keyFile))
      else {
        val generated = new RSAKeyGenerator(2048).keyID("load-1").generate()
        write(keyFile, generated.toJSONString)
        generated
      }
    write(out.resolve("jwks.json"), new JWKSet(signingKey.toPublicJWK).toString)

    val tokens = (1 to tokenCount.toInt).asJava
      .parallelStream()
      .map(_ => accessToken(signingKey, issuer, audience, cnf = None))
      .toList
      .asScala
    if (tokens.nonEmpty) write(out.resolve("tokens.txt"), tokens.mkString("\n") + "\n")

    val dpopKey: ECKey = new ECKeyGenerator(Curve.P_256).keyID("dpop").generate()
    val jkt            = dpopKey.toPublicJWK.computeThumbprint().toString
    val bound          = accessToken(signingKey, issuer, audience, cnf = Some(jkt))
    val ath            = DpopVerifier.accessTokenHash(bound)
    val proofs         = (0 until proofCount.toInt).asJava
      .parallelStream()
      .map(i => proof(dpopKey, htu, ath, nonces.lift(i % math.max(1, nonces.size))))
      .toList
      .asScala
    write(out.resolve("dpop.txt"), (bound +: proofs).mkString("\n") + "\n")

    println(
      s"Wrote ${tokens.size} tokens and ${proofs.size} DPoP proofs to ${out.toAbsolutePath}"
    )
  }

  private def accessToken(
      key: RSAKey,
      issuer: String,
      audience: String,
      cnf: Option[String]
  ): String = {
    val now     = System.currentTimeMillis()
    val builder = new JWTClaimsSet.Builder()
      .issuer(issuer)
      .audience(audience)
      .subject("user-" + UUID.randomUUID().toString.take(8))
      .claim("client_id", "load-test")
      .claim("scope", "accounts:read")
      .jwtID(UUID.randomUUID().toString)
      .issueTime(new Date(now))
      .expirationTime(new Date(now + 3_600_000L))
    cnf.foreach(jkt => builder.claim("cnf", java.util.Map.of("jkt", jkt)))
    val jwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.RS256)
        .keyID(key.getKeyID)
        .`type`(new JOSEObjectType("at+jwt"))
        .build(),
      builder.build()
    )
    jwt.sign(new RSASSASigner(key))
    jwt.serialize()
  }

  private def proof(key: ECKey, htu: String, ath: String, nonce: Option[String]): String = {
    val claims = new JWTClaimsSet.Builder()
      .jwtID(UUID.randomUUID().toString)
      .claim("htm", "GET")
      .claim("htu", htu)
      .claim("ath", ath)
      .issueTime(new Date())
    nonce.foreach(claims.claim("nonce", _))
    val jwt = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.ES256)
        .`type`(new JOSEObjectType("dpop+jwt"))
        .jwk(key.toPublicJWK)
        .build(),
      claims.build()
    )
    jwt.sign(new ECDSASigner(key))
    jwt.serialize()
  }

  private def write(path: Path, content: String): Unit = {
    val _ = Files.write(path, content.getBytes(StandardCharsets.US_ASCII))
  }

}
