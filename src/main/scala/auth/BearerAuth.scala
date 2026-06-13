package auth

import scala.concurrent.duration.FiniteDuration

import cats.Monad
import cats.data.{EitherT, Kleisli, OptionT}
import cats.effect.Clock
import cats.syntax.all.*
import org.http4s.headers.{Authorization, `Content-Type`}
import org.http4s.server.AuthMiddleware
import org.http4s.{
  AuthScheme,
  AuthedRoutes,
  Credentials,
  Header,
  MediaType,
  Request,
  Response,
  Status
}
import org.typelevel.ci.*
import auth.given

/** http4s middleware enforcing OAuth 2.0 access-token authentication for
  * financial-grade / government APIs.
  *
  * Specs enforced:
  *   - RFC 6750 — `Bearer` scheme, `WWW-Authenticate` challenges and error
  *     codes
  *   - RFC 9068 — JWT access-token validation (via [[JwtValidator]])
  *   - RFC 9449 — DPoP sender-constrained tokens: `Authorization: DPoP …` plus
  *     a `DPoP` proof header, bound through the token's `cnf.jkt` claim
  *   - RFC 8705 — mutual-TLS certificate-bound tokens via `cnf.x5t#S256`
  *   - RFC 9470 — step-up authentication ([[requireAcr]])
  *   - OAuth 2.1 hygiene — access tokens in the query string are rejected
  *     outright, only one credential may be presented, and every authentication
  *     response carries `Cache-Control: no-store`
  *
  * Behaviour:
  *   - no credentials → `401` with `Bearer` (and, if enabled, `DPoP`)
  *     challenges
  *   - token in the query string or multiple credentials →
  *     `400 invalid_request`
  *   - failed validation or binding → `401 invalid_token`
  *   - missing/invalid/replayed DPoP proof → `401 invalid_dpop_proof`
  *   - valid token but missing scopes → `403 insufficient_scope`
  *   - valid token but insufficient `acr` / stale `auth_time` →
  *     `401 insufficient_user_authentication`
  *   - keys unavailable → `503` with `Retry-After` (fail closed)
  *
  * Error bodies and challenge parameters only ever contain fixed,
  * library-controlled strings — no token contents, claim values or upstream
  * error messages.
  */
object BearerAuth {

  private val DpopScheme: AuthScheme = ci"DPoP"

  private enum TokenScheme derives CanEqual {
    case Bearer
    case Dpop
  }

  /** @param senderConstraint
    *   whether plain bearer tokens are still accepted; see
    *   [[SenderConstraintPolicy]]. `cnf` bindings present on a token are always
    *   enforced regardless of this setting.
    * @param dpop
    *   enables the `DPoP` scheme and proof validation when set
    * @param clientCertificates
    *   enables mTLS certificate-bound token checks when set
    */
  def middleware[F[_]: Monad](
      validator: JwtValidator[F],
      events: AuthEvents[F],
      realm: String = "api",
      senderConstraint: SenderConstraintPolicy =
        SenderConstraintPolicy.EnforceWhenBound,
      dpop: Option[DpopVerifier[F]] = None,
      clientCertificates: Option[ClientCertificates[F]] = None
  ): AuthMiddleware[F, AuthContext] = {

    val dpopAlgs: Option[String] =
      dpop.map(_.algorithms.toSeq.map(_.getName).sorted.mkString(" "))

    def fail(error: AuthError, detail: String): F[Either[AuthError, Unit]] =
      events.authFailed(error, detail).as(error.asLeft)

    val pass: F[Either[AuthError, Unit]] = ().asRight[AuthError].pure[F]

    // RFC 9449: a cnf.jkt-bound token requires the DPoP scheme and a valid proof;
    // a bound token downgraded to Bearer, or the DPoP scheme without a binding,
    // is rejected.
    def dpopCheck(
        req: Request[F],
        scheme: TokenScheme,
        token: String,
        ctx: AuthContext
    ): F[Either[AuthError, Unit]] =
      (scheme, ctx.dpopKeyThumbprint) match {
        case (TokenScheme.Dpop, Some(jkt)) =>
          dpop.fold(
            fail(
              AuthError.InvalidToken.WrongScheme,
              "DPoP scheme used but DPoP is not enabled"
            )
          )(
            _.verify(req, token, jkt)
          )
        case (TokenScheme.Dpop, None) =>
          fail(
            AuthError.InvalidToken.NotDpopBound,
            "DPoP scheme with a token lacking cnf.jkt"
          )
        case (TokenScheme.Bearer, Some(_)) =>
          fail(
            AuthError.InvalidToken.DpopBindingRequired,
            "DPoP-bound token presented as Bearer"
          )
        case (TokenScheme.Bearer, None) =>
          pass
      }

    // RFC 8705 §3: a cnf.x5t#S256-bound token is only valid on a connection that
    // presented the matching client certificate.
    def mtlsCheck(
        req: Request[F],
        ctx: AuthContext
    ): F[Either[AuthError, Unit]] =
      ctx.certificateThumbprint match {
        case None           => pass
        case Some(expected) =>
          clientCertificates match {
            case None =>
              fail(
                AuthError.InvalidToken.CertificateBindingFailed,
                "certificate-bound token but no client certificate source is configured"
              )
            case Some(certs) =>
              certs.extract(req).flatMap {
                case Some(cert) if Mtls.matches(cert, expected) => pass
                case Some(_)                                    =>
                  fail(
                    AuthError.InvalidToken.CertificateBindingFailed,
                    "certificate thumbprint mismatch"
                  )
                case None =>
                  fail(
                    AuthError.InvalidToken.CertificateBindingFailed,
                    "no client certificate presented"
                  )
              }
          }
      }

    def policyCheck(ctx: AuthContext): F[Either[AuthError, Unit]] =
      senderConstraint match {
        case SenderConstraintPolicy.Required if !ctx.isSenderConstrained =>
          fail(
            AuthError.InvalidToken.SenderConstraintRequired,
            "bearer token without cnf binding"
          )
        case _ => pass
      }

    val authenticate: Kleisli[F, Request[F], Either[AuthError, AuthContext]] =
      Kleisli { req =>
        extractCredentials(req, dpopEnabled = dpop.isDefined) match {
          case Left(err) =>
            events
              .authFailed(err, "no usable credentials on request")
              .as(err.asLeft)
          case Right((scheme, token)) =>
            (for {
              ctx <- EitherT(validator.validate(token))
              _ <- EitherT(dpopCheck(req, scheme, token, ctx))
              _ <- EitherT(mtlsCheck(req, ctx))
              _ <- EitherT(policyCheck(ctx))
            } yield ctx).value
        }
      }

    val onFailure: AuthedRoutes[AuthError, F] =
      Kleisli(req =>
        OptionT.pure[F](errorResponse(req.context, realm, dpopAlgs))
      )

    AuthMiddleware(authenticate, onFailure)
  }

  /** Require every scope in `required` on top of authentication. Compose per
    * route group, e.g. `requireScopes(Set("payments:write"))(paymentRoutes)`.
    */
  def requireScopes[F[_]: Monad](required: Set[String], realm: String = "api")(
      routes: AuthedRoutes[AuthContext, F]
  ): AuthedRoutes[AuthContext, F] =
    Kleisli { req =>
      if (required.subsetOf(req.context.scopes)) routes(req)
      else
        OptionT.pure[F](
          errorResponse(AuthError.InsufficientScope(required), realm, None)
        )
    }

  /** Step-up authentication (RFC 9470): require that the user authenticated
    * with one of `acceptableAcrValues` and, if `maxAge` is set, recently
    * enough. On failure the client receives
    * `401 insufficient_user_authentication` with the `acr_values` / `max_age`
    * the authorization server should be asked for — apply to high-risk routes
    * such as payment initiation or beneficiary changes.
    */
  def requireAcr[F[_]: Monad: Clock](
      acceptableAcrValues: Set[String],
      maxAge: Option[FiniteDuration] = None,
      realm: String = "api"
  )(routes: AuthedRoutes[AuthContext, F]): AuthedRoutes[AuthContext, F] =
    Kleisli { req =>
      val ctx = req.context
      val acrOk = acceptableAcrValues.isEmpty || ctx.acr.exists(
        acceptableAcrValues.contains
      )
      OptionT
        .liftF(maxAge match {
          case None        => true.pure[F]
          case Some(limit) =>
            Clock[F].realTimeInstant.map { now =>
              ctx.authTime
                .exists(at => !at.plusSeconds(limit.toSeconds).isBefore(now))
            }
        })
        .flatMap { freshEnough =>
          if (acrOk && freshEnough) routes(req)
          else
            OptionT.pure[F](
              errorResponse(
                AuthError
                  .InsufficientUserAuthentication(acceptableAcrValues, maxAge),
                realm,
                None
              )
            )
        }
    }

  private def extractCredentials[F[_]](
      req: Request[F],
      dpopEnabled: Boolean
  ): Either[AuthError, (TokenScheme, String)] =
    // OAuth 2.1 / RFC 6750 §2.3: query-string tokens leak via logs, referrers and
    // history; reject them even when an Authorization header is also present.
    if (req.uri.query.pairs.exists(_._1 == "access_token"))
      Left(AuthError.InvalidRequest.TokenInQuery)
    else if (req.headers.headers.count(_.name == Authorization.name) > 1)
      Left(AuthError.InvalidRequest.MultipleCredentials)
    else
      req.headers.get[Authorization] match {
        case Some(Authorization(Credentials.Token(AuthScheme.Bearer, token))) =>
          Right((TokenScheme.Bearer, token))
        case Some(Authorization(Credentials.Token(DpopScheme, token)))
            if dpopEnabled =>
          Right((TokenScheme.Dpop, token))
        case Some(_) =>
          Left(AuthError.InvalidToken.WrongScheme)
        case None =>
          Left(AuthError.MissingToken)
      }

  private[auth] def errorResponse[F[_]](
      error: AuthError,
      realm: String,
      dpopAlgs: Option[String]
  ): Response[F] = {
    def bearer(params: String): String = s"""Bearer realm="$realm"$params"""
    def withDpopChallenge(challenge: String): String =
      (challenge :: dpopAlgs.map(a => s"""DPoP algs="$a"""").toList)
        .mkString(", ")

    error match {
      case AuthError.MissingToken =>
        challengeResponse(
          Status.Unauthorized,
          withDpopChallenge(bearer("")),
          body = None
        )
      case AuthError.InvalidRequest(reason) =>
        challengeResponse(
          Status.BadRequest,
          bearer(s""", error="invalid_request", error_description="$reason""""),
          body = Some(("invalid_request", reason))
        )
      case AuthError.InvalidToken(reason) =>
        challengeResponse(
          Status.Unauthorized,
          withDpopChallenge(
            bearer(s""", error="invalid_token", error_description="$reason"""")
          ),
          body = Some(("invalid_token", reason))
        )
      case AuthError.InvalidDpopProof(reason) =>
        val algs = dpopAlgs.fold("")(a => s""", algs="$a"""")
        challengeResponse(
          Status.Unauthorized,
          s"""DPoP realm="$realm"$algs, error="invalid_dpop_proof", error_description="$reason"""",
          body = Some(("invalid_dpop_proof", reason))
        )
      case AuthError.InsufficientScope(required) =>
        val scope = required.toSeq.sorted.mkString(" ")
        challengeResponse(
          Status.Forbidden,
          bearer(s""", error="insufficient_scope", scope="$scope""""),
          body = Some(("insufficient_scope", s"required scope: $scope"))
        )
      case AuthError.InsufficientUserAuthentication(acrValues, maxAge) =>
        val description =
          "stronger or more recent user authentication is required"
        val acrParam =
          if (acrValues.isEmpty) ""
          else s""", acr_values="${acrValues.toSeq.sorted.mkString(" ")}""""
        val maxAgeParam = maxAge.fold("")(d => s", max_age=${d.toSeconds}")
        challengeResponse(
          Status.Unauthorized,
          bearer(
            s""", error="insufficient_user_authentication", error_description="$description"$acrParam$maxAgeParam"""
          ),
          body = Some(("insufficient_user_authentication", description))
        )
      case AuthError.ValidationUnavailable =>
        Response[F](Status.ServiceUnavailable)
          .putHeaders(Header.Raw(ci"Retry-After", "5"), noStore)
    }
  }

  private def noStore: Header.Raw = Header.Raw(ci"Cache-Control", "no-store")

  private def challengeResponse[F[_]](
      status: Status,
      challenge: String,
      body: Option[(String, String)]
  ): Response[F] = {
    val base = Response[F](status)
      .putHeaders(Header.Raw(ci"WWW-Authenticate", challenge), noStore)
    body.fold(base) { case (code, description) =>
      base
        .withEntity(s"""{"error":"$code","error_description":"$description"}""")
        .withContentType(`Content-Type`(MediaType.application.json))
    }
  }
}
