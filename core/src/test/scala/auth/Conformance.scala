package auth

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.cert.CertificateFactory
import java.security.MessageDigest
import java.util.Base64

import scala.concurrent.duration.*

/**
  * The authentication conformance suite: one list of requests and, for each, what a client must
  * see. Every service implementation runs it against its own middleware (the http4s service and the
  * ZIO service each have a `ConformanceSpec`), so two implementations that each pass make the same
  * decisions — status, challenge headers and body — without either depending on the other.
  *
  * Expectations are stated as the [[AuthError]] (or authenticated subject) the case must produce;
  * the wire form is derived from the shared [[AuthChallenge]]. DPoP is off in both runners.
  */
object Conformance {

  enum Denylist derives CanEqual {

    case Clear
    case Revoked(jti: String)
    case Down

  }

  /**
    * @param expected
    *   the error the request must be rejected with, or the subject it must authenticate as
    */
  final case class Case(
      name: String,
      authorization: List[String],
      expected: Either[AuthError, String],
      target: String = "/me",
      denylist: Denylist = Denylist.Clear
  )

  /**
    * What a client observes: status, the challenge-related headers, and the body.
    */
  final case class Seen(status: Int, headers: Map[String, String], body: String)

  val Realm: String = "api"

  /**
    * The headers compared; anything else (dates, request ids, lengths) is framework detail.
    */
  val Compared: List[String] = List("WWW-Authenticate", "Cache-Control", "Retry-After")

  /**
    * The protected route every runner mounts at `/me` answers with this body.
    */
  def body(ctx: AuthContext): String = s"sub=${ctx.subject}"

  def expected(c: Case): Seen =
    c.expected match {
      case Right(subject) => Seen(200, Map.empty, s"sub=$subject")
      case Left(error)    =>
        val challenge = AuthChallenge.of(error, Realm, dpopAlgs = None)
        Seen(
          challenge.status,
          challenge.headers.filter { case (name, _) => Compared.contains(name) }.toMap,
          challenge.jsonBody.getOrElse("")
        )
    }

  lazy val cases: List[Case] = {
    import TestTokens.*
    def bearer(token: String) = List(s"Bearer $token")
    val subject               = "user-123"
    List(
      Case("valid bearer token", bearer(sign(claims())), Right(subject)),
      Case("lowercase scheme", List(s"bearer ${sign(claims())}"), Right(subject)),
      Case("no credentials", Nil, Left(AuthError.MissingToken)),
      Case(
        "signed by an unknown key",
        bearer(sign(claims(), key = rogueKey)),
        Left(AuthError.InvalidToken.Rejected)
      ),
      Case(
        "expired",
        bearer(sign(claims(expiresIn = (-10).minutes))),
        Left(AuthError.InvalidToken.Rejected)
      ),
      Case(
        "token in the query string",
        bearer(sign(claims())),
        Left(AuthError.InvalidRequest.TokenInQuery),
        target = "/me?access_token=abc"
      ),
      Case(
        "two Authorization headers",
        bearer(sign(claims())) ++ bearer(sign(claims())),
        Left(AuthError.InvalidRequest.MultipleCredentials)
      ),
      Case("Basic scheme", List("Basic dXNlcjpwYXNz"), Left(AuthError.InvalidToken.WrongScheme)),
      Case(
        "DPoP scheme while DPoP is off",
        List(s"DPoP ${sign(claims())}"),
        Left(AuthError.InvalidToken.WrongScheme)
      ),
      Case("unparseable header", List("Bearer a b"), Left(AuthError.MissingToken)),
      Case(
        "oversized token",
        List("Bearer " + "a" * 9000),
        Left(AuthError.InvalidToken.Oversized)
      ),
      Case(
        "DPoP-bound token presented as Bearer",
        bearer(sign(dpopBoundClaims())),
        Left(AuthError.InvalidToken.DpopBindingRequired)
      ),
      Case(
        "certificate-bound token presented as Bearer",
        bearer(sign(mtlsBoundClaims(certificateThumbprint(clientCertPem)))),
        Left(AuthError.InvalidToken.CertificateBindingFailed)
      ),
      Case(
        "revoked token",
        bearer(sign(claims(jti = Some("jti-conformance-revoked")))),
        Left(AuthError.InvalidToken.Revoked),
        denylist = Denylist.Revoked("jti-conformance-revoked")
      ),
      Case(
        "revocation store unavailable (fail closed)",
        bearer(sign(claims(jti = Some("jti-conformance-down")))),
        Left(AuthError.ValidationUnavailable),
        denylist = Denylist.Down
      )
    )
  }

  /**
    * The denylist answer a runner's store must give for `jti` in state `state`.
    */
  def isRevoked(state: Denylist, jti: String): Either[Throwable, Boolean] =
    state match {
      case Denylist.Clear         => Right(false)
      case Denylist.Revoked(that) => Right(that == jti)
      case Denylist.Down          => Left(new java.util.concurrent.TimeoutException("store stalled"))
    }

  // RFC 8705 x5t#S256: base64url(SHA-256(DER certificate)).
  private def certificateThumbprint(pem: String): String = {
    val certificate = CertificateFactory
      .getInstance("X.509")
      .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))
    Base64.getUrlEncoder.withoutPadding.encodeToString(
      MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded)
    )
  }

}
