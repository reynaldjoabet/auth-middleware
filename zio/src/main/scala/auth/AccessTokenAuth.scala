package auth

import zio.*
import zio.http.*

/**
  * Access-token authentication as a zio-http `HandlerAspect` — the ZIO counterpart of the http4s
  * service's `AccessTokenAuth.middleware` for the Bearer scheme. Routes wrapped with [[aspect]]
  * read the authenticated principal with `withContext((ctx: AuthContext) => …)`.
  *
  * Credential extraction ([[auth.CredentialExtraction]]) and challenge rendering
  * ([[auth.AuthChallenge]]) are the shared implementations, so a client gets the same status,
  * `WWW-Authenticate`, headers and body from either middleware.
  *
  * Bearer only: the DPoP scheme is not implemented here, and there is no client-certificate source.
  * As in the http4s middleware configured the same way, a `cnf`-bound token presented as Bearer is
  * therefore rejected — a DPoP-bound one as `dpop_binding_required`, a certificate-bound one
  * because no certificate can be checked.
  */
object AccessTokenAuth {

  def aspect(
      validator: AccessTokenValidator,
      events: AuthEvents,
      realm: String = "api"
  ): HandlerAspect[Any, AuthContext] =
    HandlerAspect.interceptIncomingHandler(Handler.fromFunctionZIO[Request] { request =>
      CredentialExtraction.extract(
        tokenInQuery = request.url.queryParams.hasQueryParam("access_token"),
        authorization = request.headers.rawHeaders("Authorization").toList,
        dpopEnabled = false
      ) match {
        case Left(error) =>
          events.failed(error, "no usable credentials on request") *>
            ZIO.fail(challenge(error, realm))
        case Right((_, token)) =>
          validator.validate(token).flatMap {
            case Left(error) => ZIO.fail(challenge(error, realm))
            case Right(ctx)  =>
              bearerBindingFailure(ctx) match {
                case None                  => ZIO.succeed((request, ctx))
                case Some((error, detail)) =>
                  events.failed(error, detail) *> ZIO.fail(challenge(error, realm))
              }
          }
      }
    })

  /**
    * The sender-constraint check for a token presented as Bearer, with neither DPoP nor a
    * client-certificate source available.
    */
  private def bearerBindingFailure(ctx: AuthContext): Option[(AuthError, String)] =
    ctx.confirmation match {
      case None                            => None
      case Some(ConfirmationClaim.DPoP(_)) =>
        Some((AuthError.InvalidToken.DpopBindingRequired, "DPoP-bound token presented as Bearer"))
      case Some(ConfirmationClaim.MutualTls(_)) =>
        Some(
          (
            AuthError.InvalidToken.CertificateBindingFailed,
            "certificate-bound token but no client certificate source is configured"
          )
        )
    }

  /**
    * The shared challenge for `error`, as a zio-http response.
    */
  def challenge(error: AuthError, realm: String = "api"): Response = {
    val rendered = AuthChallenge.of(error, realm, dpopAlgs = None)
    val headers  = Headers(rendered.headers.map { case (name, value) =>
      Header.Custom(name, value)
    }*)
    rendered.jsonBody match {
      case None       => Response(status = Status.fromInt(rendered.status), headers = headers)
      case Some(json) =>
        Response(
          status = Status.fromInt(rendered.status),
          headers = headers ++ Headers(Header.ContentType(MediaType.application.json)),
          body = Body.fromString(json)
        )
    }
  }

}
