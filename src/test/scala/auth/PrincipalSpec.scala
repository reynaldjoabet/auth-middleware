package auth

import java.util.Date

import com.nimbusds.jwt.JWTClaimsSet

import munit.FunSuite

/** Covers claim extraction that the action pipeline relies on (scopes, amr,
  * cnf.jkt).
  */
class PrincipalSpec extends FunSuite {

  private def base(): JWTClaimsSet.Builder =
    new JWTClaimsSet.Builder()
      .subject("user-123")
      .claim("client_id", "mobile-app")
      .issueTime(new Date())
      .expirationTime(new Date(System.currentTimeMillis() + 60000))

  test("parses space-delimited scopes") {
    val p = Principal.from(
      base().claim("scope", "accounts:read payments:write").build()
    )
    assert(p.hasScope("accounts:read"))
    assert(p.hasScope("payments:write"))
    assert(!p.hasScope("admin"))
  }

  test("parses amr as a string list") {
    val p = Principal.from(
      base().claim("amr", java.util.List.of("pwd", "webauthn")).build()
    )
    assert(p.amr.contains("webauthn"))
    assert(p.amr.contains("pwd"))
  }

  test("extracts cnf.jkt for a DPoP-bound token") {
    val p = Principal.from(
      base().claim("cnf", java.util.Map.of("jkt", "Gpzr...thumb")).build()
    )
    assertEquals(p.cnfJkt, "Gpzr...thumb")
  }

  test("cnfJkt is null for a plain bearer token") {
    val p = Principal.from(base().claim("scope", "accounts:read").build())
    assertEquals(p.cnfJkt, null)
    assert(p.amr.isEmpty)
    assertEquals(p.subject, "user-123")
    assertEquals(p.clientId, "mobile-app")
  }
}
