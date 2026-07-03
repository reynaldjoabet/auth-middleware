package auth

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
import auth.dpop.DpopVerifier
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
  *   - nonce enforcement on (RFC 9449 §8): a proof without a fresh
  *     server-provided nonce → `401 use_dpop_nonce` + `DPoP-Nonce`; every
  *     response to a DPoP request carries a fresh `DPoP-Nonce` for rotation
  *   - valid token but missing scopes → `403 insufficient_scope`
  *   - valid token but insufficient `acr` / stale `auth_time` →
  *     `401 insufficient_user_authentication`
  *   - keys unavailable → `503` with `Retry-After` (fail closed)
  *
  * Error bodies and challenge parameters only ever contain fixed,
  * library-controlled strings — no token contents, claim values or upstream
  * error messages. The one dynamic value is the `DPoP-Nonce` header: a
  * server-minted random nonce (RFC 9449 §8), never derived from token material.
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
    ): F[Either[AuthError, Unit]] = {
      val boundJkt =
        ctx.confirmation.collect { case ConfirmationClaim.DPoP(jkt) => jkt }
      (scheme, boundJkt) match {
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
    }

    // RFC 8705 §3: a cnf.x5t#S256-bound token is only valid on a connection that
    // presented the matching client certificate.
    def mtlsCheck(
        req: Request[F],
        ctx: AuthContext
    ): F[Either[AuthError, Unit]] =
      ctx.confirmation.collect { case ConfirmationClaim.MutualTls(x5tS256) =>
        x5tS256
      } match {
        case None                  => pass
        case Some(expectedx5tS256) =>
          clientCertificates match {
            case None =>
              fail(
                AuthError.InvalidToken.CertificateBindingFailed,
                "certificate-bound token but no client certificate source is configured"
              )
            case Some(certs) =>
              certs.extract(req).flatMap {
                case Some(cert) if Mtls.matches(cert, expectedx5tS256) => pass
                case Some(_)                                           =>
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

    val base = AuthMiddleware(authenticate, onFailure)

    // RFC 9449 §8.2 nonce rotation: when nonces are enforced, every response
    // to a DPoP-scheme request carries a fresh `DPoP-Nonce` (unless one is
    // already set, e.g. by the use_dpop_nonce challenge). Rotating on success
    // keeps steady state at one round trip per call; rotating on failure hands
    // the client the nonce it needs to recover immediately — a proof rejected
    // after its nonce was consumed would otherwise cost two more round trips.
    dpop.flatMap(_.nonces) match {
      case None            => base
      case Some(validator) =>
        routes =>
          Kleisli { (req: Request[F]) =>
            base(routes)(req).semiflatMap { resp =>
              if (
                !usesDpopScheme(req) ||
                resp.headers.get(DpopNonceHeader).isDefined
              )
                resp.pure[F]
              else
                validator.createNonce.map(n =>
                  resp.putHeaders(Header.Raw(DpopNonceHeader, n.value: String))
                )
            }
          }
    }
  }

  private val DpopNonceHeader = ci"DPoP-Nonce"

  private def usesDpopScheme[F[_]](req: Request[F]): Boolean =
    req.headers.get[Authorization].exists {
      case Authorization(Credentials.Token(scheme, _)) => scheme == DpopScheme
      case _                                           => false
    }

  /** Require every scope in `required` on top of authentication. Compose per
    * route group, e.g. `requireScopes(Set("payments:write"))(paymentRoutes)`.
    */
  def requireScopes[F[_]: Monad](
      required: Set[ScopeToken],
      realm: String = "api"
  )(
      routes: AuthedRoutes[AuthContext, F]
  ): AuthedRoutes[AuthContext, F] =
    Kleisli { req =>
      if (required.subsetOf(req.context.scopes)) routes(req)
      else
        OptionT.pure[F](
          errorResponse(
            AuthError.InsufficientScope(required.map(_.value)),
            realm,
            None
          )
        )
    }

  /** Require that an end user is present on the token — i.e. reject
    * machine-to-machine (`client_credentials`) tokens on this route. Apply to
    * endpoints that act on behalf of a person; leave it off for service/batch
    * endpoints, which are gated on `client_id` + scopes instead.
    *
    * Failure is reported as `401 insufficient_user_authentication` (RFC 9470):
    * the token is valid, but the route requires a user and the token has none.
    * `isUserPresent` defaults to [[AuthContext.userPresent]]; override it with
    * an authorization-server-specific signal if needed.
    */
  def requireUser[F[_]: Monad](
      isUserPresent: AuthContext => Boolean = AuthContext.userPresent,
      realm: String = "api"
  )(routes: AuthedRoutes[AuthContext, F]): AuthedRoutes[AuthContext, F] =
    Kleisli { req =>
      if (isUserPresent(req.context)) routes(req)
      else
        OptionT.pure[F](
          errorResponse(
            AuthError.InsufficientUserAuthentication(Seq.empty, None),
            realm,
            None
          )
        )
    }

  /** Step-up authentication (RFC 9470): require that the user authenticated
    * with one of the given `acr` values. Takes at least one value (head +
    * tail), so it can never be a silent no-op — there is no empty-set form that
    * admits everyone. On failure the client receives
    * `401 insufficient_user_authentication` with `acr_values`. For "any acr but
    * recently authenticated" use [[requireFreshAuth]]; compose the two for
    * "this acr AND recent".
    *
    * An M2M token has no `acr` (RFC 9068 §2.2.1), so this also implies a user.
    */
  def requireAcr[F[_]: Monad](first: Acr, rest: Acr*)(
      routes: AuthedRoutes[AuthContext, F],
      realm: String = "api"
  ): AuthedRoutes[AuthContext, F] = {
    // Preserve declared order (RFC 9470 §3 acr_values are "in order of
    // preference") and dedup. `acr` is a single Option, so the predicate runs
    // at most once per request over a handful of values — a plain Seq.contains
    // is fine, no Set needed.
    val requiredAcrValues = (first +: rest).distinct
    Kleisli { req =>
      if (req.context.acr.exists(requiredAcrValues.contains)) routes(req)
      else
        OptionT.pure[F](
          errorResponse(
            AuthError.InsufficientUserAuthentication(
              requiredAcrValues.map(a => a.value: String),
              None
            ),
            realm,
            None
          )
        )
    }
  }

  /** Step-up freshness (RFC 9470): require that the user authenticated within
    * `maxAge` (via the `auth_time` claim), regardless of `acr`. Since
    * `auth_time` is a user-authentication claim, this also implies a user is
    * present. Compose with [[requireAcr]] for "this acr, authenticated within
    * `maxAge`". On failure the client receives
    * `401 insufficient_user_authentication` with `max_age`.
    */
  def requireFreshAuth[F[_]: Monad: Clock](
      maxAge: MaxAuthAge,
      realm: String = "api"
  )(routes: AuthedRoutes[AuthContext, F]): AuthedRoutes[AuthContext, F] =
    Kleisli { req =>
      OptionT
        .liftF(Clock[F].realTimeInstant.map { now =>
          req.context.authTime
            .exists(at => !at.plusSeconds(maxAge.value.toLong).isBefore(now))
        })
        .flatMap { fresh =>
          if (fresh) routes(req)
          else
            OptionT.pure[F](
              errorResponse(
                AuthError
                  .InsufficientUserAuthentication(Seq.empty, Some(maxAge)),
                realm,
                None
              )
            )
        }
    }

  /** Adds an ACR step-up authorization check requiring `mfaAcr` (multi-factor
    * auth; defaults to `acr3`). Enforces authentication recency (default 5
    * minutes) per NIST SP 800-63B. Returns a `WWW-Authenticate` challenge (`401
    * insufficient_user_authentication`) when step-up is required.
    *
    * A convenience preset composing [[requireAcr]] over [[requireFreshAuth]].
    * Because the two gates short-circuit independently, a token failing both
    * receives the `acr_values` challenge first and the `max_age` challenge on
    * retry; if you need both in a single challenge, aggregate the requirements
    * instead.
    */
  def requireMfa[F[_]: Monad: Clock](
      mfaAcr: Acr = Acr("acr3"),
      maxAge: MaxAuthAge = MaxAuthAge(300),
      realm: String = "api"
  )(routes: AuthedRoutes[AuthContext, F]): AuthedRoutes[AuthContext, F] =
    requireAcr(mfaAcr)(requireFreshAuth(maxAge, realm)(routes), realm)

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
    val algsParam = dpopAlgs.fold("")(a => s""", algs="$a"""")

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
        challengeResponse(
          Status.Unauthorized,
          s"""DPoP realm="$realm"$algsParam, error="invalid_dpop_proof", error_description="$reason"""",
          body = Some(("invalid_dpop_proof", reason))
        )
      case AuthError.UseDpopNonce(nonce) =>
        // RFC 9449 §8-9: hand the client a fresh DPoP-Nonce to echo in the
        // `nonce` claim of its next proof. Not a hard failure — a challenge.
        val description =
          "a DPoP proof carrying a server-provided nonce is required"
        challengeResponse(
          Status.Unauthorized,
          s"""DPoP realm="$realm"$algsParam, error="use_dpop_nonce", error_description="$description"""",
          body = Some(("use_dpop_nonce", description))
        ).putHeaders(Header.Raw(DpopNonceHeader, nonce.value: String))
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
        // Emit acr_values in the caller's preference order (RFC 9470 §3); do
        // not sort. max_age is a MaxAuthAge, so non-negativity (RFC 9470 §3) is
        // guaranteed by the type — no runtime clamp needed.
        val acrParam =
          if (acrValues.isEmpty) ""
          else s""", acr_values="${acrValues.mkString(" ")}""""
        val maxAgeParam =
          maxAge.fold("")(m => s", max_age=${m.value}")
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
