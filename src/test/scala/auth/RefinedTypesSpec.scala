package auth

import munit.FunSuite

/** The Iron refined types in `package.scala` are the input-validation boundary:
  * every untrusted string (issuer, thumbprints, JWT structure, nonces, scopes)
  * is admitted only if it matches. Their constraints encode security rules —
  * e.g. an issuer must be https and carry no query/fragment, a thumbprint must
  * be exactly a base64url SHA-256 — so they are tested directly.
  */
class RefinedTypesSpec extends FunSuite {

  private def accepts(rt: String => Option[Any], name: String)(
      vs: String*
  ): Unit =
    vs.foreach(v => assert(rt(v).isDefined, s"$name should ACCEPT: [$v]"))

  private def rejects(rt: String => Option[Any], name: String)(
      vs: String*
  ): Unit =
    vs.foreach(v => assert(rt(v).isEmpty, s"$name should REJECT: [$v]"))

  private val b64 = "A" * 43 // 43-char base64url = a SHA-256 thumbprint

  test(
    "Issuer: https only, no query or fragment (token substitution surface)"
  ) {
    accepts(Issuer.option, "Issuer")(
      "https://auth.example.com",
      "https://auth.example.com/realms/fintech"
    )
    rejects(Issuer.option, "Issuer")(
      "http://auth.example.com", // not https
      "https://auth.example.com?x=1", // query forbidden
      "https://auth.example.com#f", // fragment forbidden
      "https://has space.com", // whitespace
      "ftp://auth.example.com",
      ""
    )
  }

  test("Htu: https, no query or fragment (RFC 9449 htu grammar)") {
    accepts(Htu.option, "Htu")("https://api.example.com/accounts")
    rejects(Htu.option, "Htu")(
      "https://api.example.com/accounts?page=2",
      "https://api.example.com/a#b",
      "http://api.example.com/accounts"
    )
  }

  test("JwkThumbprint: exactly 43 base64url chars, no padding") {
    accepts(JwkThumbprint.option, "JwkThumbprint")(b64, "-_" + ("a" * 41))
    rejects(JwkThumbprint.option, "JwkThumbprint")(
      "A" * 42, // too short
      "A" * 44, // too long
      ("A" * 42) + "=", // padding char, not base64url
      ("A" * 42) + "+", // '+' is base64, not base64url
      ("A" * 42) + "/",
      ""
    )
  }

  test("Certificate/AccessToken thumbprints share the SHA-256 base64url rule") {
    accepts(CertificateThumbprint.option, "CertificateThumbprint")(b64)
    accepts(AccessTokenHash.option, "AccessTokenHash")(b64)
    rejects(CertificateThumbprint.option, "CertificateThumbprint")("A" * 44)
    rejects(AccessTokenHash.option, "AccessTokenHash")("short")
  }

  test(
    "SignedJwt/DpopProofJwt: three non-empty segments (rejects alg:none shape)"
  ) {
    accepts(SignedJwt.option, "SignedJwt")("aaa.bbb.ccc", "h-_.p-_.s-_")
    rejects(SignedJwt.option, "SignedJwt")(
      "aaa.bbb", // unsecured / 2-segment
      "aaa..ccc", // empty middle — the alg:none `header..` shape
      "aaa.bbb.", // empty signature
      ".bbb.ccc", // empty header
      "aaa.bbb.ccc.ddd", // 5-part JWE, not a signed JWT here
      "not-a-jwt"
    )
    accepts(DpopProofJwt.option, "DpopProofJwt")("aaa.bbb.ccc")
    rejects(DpopProofJwt.option, "DpopProofJwt")("aaa.bbb")
  }

  test(
    "ReceivedJwtId: non-blank, bounded at 256 (DoS safety for a peer value)"
  ) {
    accepts(ReceivedJwtId.option, "ReceivedJwtId")("jti-123", "a" * 256)
    rejects(ReceivedJwtId.option, "ReceivedJwtId")("", "   ", "a" * 257)
  }

  test("DpopNonce: base64url, 1..256") {
    accepts(DpopNonce.option, "DpopNonce")("abc-_123", "a" * 256)
    rejects(DpopNonce.option, "DpopNonce")("", "a" * 257, "has space", "pad=")
  }

  test("ScopeToken: RFC scope charset, 1..128") {
    accepts(ScopeToken.option, "ScopeToken")(
      "accounts.read",
      "payments:transactions:write",
      "a/b~c-d_e"
    )
    rejects(ScopeToken.option, "ScopeToken")("", "has space", "a" * 129)
  }

  test("Subject: non-blank, bounded at 255 (OIDC sub limit)") {
    accepts(Subject.option, "Subject")("user-123", "a" * 255)
    rejects(Subject.option, "Subject")("", "  ", "a" * 256)
  }
}
