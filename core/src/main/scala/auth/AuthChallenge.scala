package auth

/**
  * How an [[AuthError]] goes on the wire, independent of any HTTP library: status, headers (in
  * order) and an optional JSON body. The http4s middleware (`AccessTokenAuth`) and the ZIO one (the
  * `zio` module) both render from this, so a client sees the same challenge from either.
  *
  * Challenges follow RFC 6750 (`Bearer`), RFC 9449 (`DPoP`) and RFC 9470 (step-up); every one
  * carries `Cache-Control: no-store`.
  */
final case class AuthChallenge(
    status: Int,
    headers: List[(String, String)],
    jsonBody: Option[String]
)

object AuthChallenge {

  private val NoStore = "Cache-Control" -> "no-store"

  /**
    * @param dpopAlgs
    *   space-separated DPoP proof algorithms, when DPoP is enabled; advertised in the challenges
    */
  def of(error: AuthError, realm: String, dpopAlgs: Option[String]): AuthChallenge = {
    def bearer(params: String): String               = s"""Bearer realm="$realm"$params"""
    def withDpopChallenge(challenge: String): String =
      (challenge :: dpopAlgs.map(a => s"""DPoP algs="$a"""").toList).mkString(", ")
    val algsParam = dpopAlgs.fold("")(a => s""", algs="$a"""")

    error match {
      case AuthError.MissingToken =>
        challenge(401, withDpopChallenge(bearer("")), body = None)
      case AuthError.InvalidRequest(reason) =>
        challenge(
          400,
          bearer(s""", error="invalid_request", error_description="$reason""""),
          body = Some(("invalid_request", reason))
        )
      case AuthError.InvalidToken(reason) =>
        challenge(
          401,
          withDpopChallenge(bearer(s""", error="invalid_token", error_description="$reason"""")),
          body = Some(("invalid_token", reason))
        )
      case AuthError.InvalidDpopProof(reason) =>
        challenge(
          401,
          s"""DPoP realm="$realm"$algsParam, error="invalid_dpop_proof", error_description="$reason"""",
          body = Some(("invalid_dpop_proof", reason))
        )
      case AuthError.UseDpopNonce(nonce) =>
        // RFC 9449 §8-9: hand the client a fresh DPoP-Nonce to echo in the
        // `nonce` claim of its next proof. Not a hard failure — a challenge.
        val description = "a DPoP proof carrying a server-provided nonce is required"
        val c           = challenge(
          401,
          s"""DPoP realm="$realm"$algsParam, error="use_dpop_nonce", error_description="$description"""",
          body = Some(("use_dpop_nonce", description))
        )
        c.copy(headers = c.headers :+ ("DPoP-Nonce" -> (nonce.value: String)))
      case AuthError.InsufficientScope(required) if required.isEmpty =>
        // A role-only policy: nothing a client could request, and role names
        // are not disclosed, so the challenge carries no scope parameter.
        challenge(
          403,
          bearer(""", error="insufficient_scope""""),
          body = Some(("insufficient_scope", "the token does not grant access to this resource"))
        )
      case AuthError.InsufficientScope(required) =>
        val scope = required.toSeq.sorted.mkString(" ")
        challenge(
          403,
          bearer(s""", error="insufficient_scope", scope="$scope""""),
          body = Some(("insufficient_scope", s"required scope: $scope"))
        )
      case AuthError.InsufficientUserAuthentication(acrValues, maxAge) =>
        val description = "stronger or more recent user authentication is required"
        // Emit acr_values in the caller's preference order (RFC 9470 §3); do
        // not sort. max_age is a MaxAuthAge, so non-negativity (RFC 9470 §3) is
        // guaranteed by the type — no runtime clamp needed.
        val acrParam =
          if (acrValues.isEmpty) "" else s""", acr_values="${acrValues.mkString(" ")}""""
        val maxAgeParam = maxAge.fold("")(m => s", max_age=${m.value}")
        challenge(
          401,
          bearer(
            s""", error="insufficient_user_authentication", error_description="$description"$acrParam$maxAgeParam"""
          ),
          body = Some(("insufficient_user_authentication", description))
        )
      case AuthError.ValidationUnavailable =>
        AuthChallenge(503, List("Retry-After" -> "5", NoStore), jsonBody = None)
    }
  }

  private def challenge(
      status: Int,
      wwwAuthenticate: String,
      body: Option[(String, String)]
  ): AuthChallenge =
    AuthChallenge(
      status,
      List("WWW-Authenticate" -> wwwAuthenticate, NoStore),
      body.map { case (code, description) =>
        s"""{"error":"$code","error_description":"$description"}"""
      }
    )

}
