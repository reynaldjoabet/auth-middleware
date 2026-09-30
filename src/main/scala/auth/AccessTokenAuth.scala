package auth

import cats.{Monad, MonadThrow}
import cats.data.{EitherT, Kleisli, OptionT}
import cats.effect.{Clock, Sync}
import cats.syntax.all.*

import org.http4s.{AuthedRequest, AuthedRoutes, Header, MediaType, Request, Response, Status}
import org.http4s.headers.{`Content-Type`, Authorization}
import org.http4s.server.AuthMiddleware
import org.typelevel.ci.*
import auth.accesstoken.AccessTokenValidator
import auth.dpop.DpopVerifier
import auth.mtls.{ClientCertificates, Mtls}

/**
  * http4s middleware enforcing OAuth 2.0 access-token authentication for financial-grade /
  * government APIs.
  *
  * Specs enforced:
  *   - RFC 6750 — `Bearer` scheme, `WWW-Authenticate` challenges and error codes
  *   - RFC 9068 — JWT access-token validation (via [[AccessTokenValidator]])
  *   - RFC 9449 — DPoP sender-constrained tokens: `Authorization: DPoP …` plus a `DPoP` proof
  *     header, bound through the token's `cnf.jkt` claim
  *   - RFC 8705 — mutual-TLS certificate-bound tokens via `cnf.x5t#S256`
  *   - RFC 9470 — step-up authentication ([[requireAcr]])
  *   - OAuth 2.1 hygiene — access tokens in the query string are rejected outright, only one
  *     credential may be presented, and every authentication response carries
  *     `Cache-Control: no-store`
  *
  * Behaviour:
  *   - no credentials → `401` with `Bearer` (and, if enabled, `DPoP`) challenges
  *   - token in the query string or multiple credentials → `400 invalid_request`
  *   - failed validation or binding → `401 invalid_token`
  *   - missing/invalid/replayed DPoP proof → `401 invalid_dpop_proof`
  *   - nonce enforcement on (RFC 9449 §8): a proof without a fresh server-provided nonce →
  *     `401 use_dpop_nonce` + `DPoP-Nonce`; every response to a DPoP request carries a fresh
  *     `DPoP-Nonce` for rotation
  *   - valid token but missing scopes → `403 insufficient_scope`
  *   - valid token but insufficient `acr` / stale `auth_time` →
  *     `401 insufficient_user_authentication`
  *   - keys unavailable → `503` with `Retry-After` (fail closed)
  *
  * Error bodies and challenge parameters only ever contain fixed, library-controlled strings — no
  * token contents, claim values or upstream error messages. The one dynamic value is the
  * `DPoP-Nonce` header: a server-minted random nonce (RFC 9449 §8), never derived from token
  * material.
  */
object AccessTokenAuth {

  private type TokenScheme = CredentialExtraction.Scheme
  private val TokenScheme = CredentialExtraction.Scheme

  /**
    * @param senderConstraint
    *   whether plain bearer tokens are still accepted; see [[SenderConstraintPolicy]]. `cnf`
    *   bindings present on a token are always enforced regardless of this setting.
    * @param dpopVerifier
    *   enables the `DPoP` scheme and proof validation when set
    * @param clientCertificates
    *   enables mTLS certificate-bound token checks when set
    */
  def middleware[F[_]: MonadThrow](
      validator: AccessTokenValidator[F],
      events: AuthEvents[F],
      realm: String = "api",
      senderConstraint: SenderConstraintPolicy = SenderConstraintPolicy.EnforceWhenBound,
      dpopVerifier: Option[DpopVerifier[F]] = None,
      clientCertificates: Option[ClientCertificates[F]] = None
  ): AuthMiddleware[F, AuthContext] = {

    val dpopAlgs: Option[String] =
      dpopVerifier.map(_.algorithms.toSeq.map(_.getName).sorted.mkString(" "))

    def fail(error: AuthError, detail: String): F[Either[AuthError, Unit]] =
      events.authFailed(error, detail).as(error.asLeft)

    val pass: F[Either[AuthError, Unit]] = ().asRight[AuthError].pure[F]

    // The token's `cnf` binding is the source of truth: the AS baked it in, and
    // it admits exactly one presentation scheme. So dispatch on the binding
    // first and check the scheme against it — each binding gets its one
    // accepting scheme and its one rejecting one, side by side. This single
    // exhaustive match is the whole scheme×binding matrix; keeping it in one
    // place is deliberate, so the invariant (an mTLS-bound token rides Bearer, a
    // DPoP-bound token rides DPoP) can't be smeared across separate checks where
    // a gap could open.
    def senderConstraintCheck(
        req: Request[F],
        scheme: TokenScheme,
        token: String,
        ctx: AuthContext
    ): F[Either[AuthError, Unit]] =
      (ctx.confirmation, scheme) match {
        // DPoP-bound (cnf.jkt): legal only on the DPoP scheme. Verify the proof
        // binds key, request and token; reject a Bearer downgrade.
        case (Some(ConfirmationClaim.DPoP(jkt)), TokenScheme.Dpop) =>
          dpopVerifier.fold(
            fail(
              AuthError.InvalidToken.WrongScheme,
              "DPoP scheme used but DPoP is not enabled"
            )
          )(_.verifyBinding(req, token, jkt))
        case (Some(ConfirmationClaim.DPoP(_)), TokenScheme.Bearer) =>
          fail(
            AuthError.InvalidToken.DpopBindingRequired,
            "DPoP-bound token presented as Bearer"
          )

        // mTLS-bound (cnf.x5t#S256): legal only on Bearer (RFC 8705). Verify the
        // client certificate; reject presentation under the DPoP scheme (same
        // client-facing error as the unbound case, distinct detail).
        case (Some(ConfirmationClaim.MutualTls(x5tS256)), TokenScheme.Bearer) =>
          verifyCertBinding(req, x5tS256)
        case (Some(ConfirmationClaim.MutualTls(_)), TokenScheme.Dpop) =>
          fail(
            AuthError.InvalidToken.NotDpopBound,
            "mTLS-bound token (cnf.x5t#S256) presented with the DPoP scheme"
          )

        // Unbound: plain bearer only; policyCheck decides whether that is
        // acceptable. The DPoP scheme requires a cnf.jkt binding.
        case (None, TokenScheme.Bearer) =>
          pass
        case (None, TokenScheme.Dpop) =>
          fail(
            AuthError.InvalidToken.NotDpopBound,
            "DPoP scheme with a token that carries no cnf binding"
          )
      }

    // RFC 8705 §3: a cnf.x5t#S256-bound token is only valid on a connection that
    // presented the matching client certificate.
    def verifyCertBinding(
        req: Request[F],
        expectedx5tS256: CertificateThumbprint
    ): F[Either[AuthError, Unit]] =
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

    def policyCheck(ctx: AuthContext): F[Either[AuthError, Unit]] =
      senderConstraint match {
        case SenderConstraintPolicy.Required if !ctx.isSenderConstrained =>
          fail(
            AuthError.InvalidToken.SenderConstraintRequired,
            "bearer token without cnf binding"
          )
        case _ => pass
      }

    // Named for the http4s `AuthMiddleware` contract, and accurate in the
    // security-literature sense: every step here is *authentication*, not
    // authorization. `validator.validate` is data-origin authentication of the
    // token (the credential is genuine, unmodified, from the trusted issuer,
    // for us); `senderConstraintCheck` is entity authentication of the sender
    // (proof of possession of the bound key/certificate). The result is a
    // verified `AuthContext` — the authenticated principal for the request.
    // Authorization proper (scopes, acr, freshness) is deliberately *not* here;
    // it is layered per route by `requireScopes`, `requireAcr`, `requireUser`
    // and `requireFreshAuth`, which consume the `AuthContext` this produces.
    val authenticate: Kleisli[F, Request[F], Either[AuthError, AuthContext]] =
      Kleisli { req =>
        extractCredentials(req, dpopEnabled = dpopVerifier.isDefined) match {
          case Left(err) =>
            events
              .authFailed(err, "no usable credentials on request")
              .as(err.asLeft)
          case Right((scheme, token)) =>
            (for {
              ctx <- EitherT(validator.validate(token))
              _   <- EitherT(senderConstraintCheck(req, scheme, token, ctx))
              _   <- EitherT(policyCheck(ctx))
            } yield ctx).value
        }
      }

    val onFailure: AuthedRoutes[AuthError, F] =
      Kleisli(req => OptionT.pure[F](errorResponse(req.context, realm, dpopAlgs)))

    val base = AuthMiddleware(authenticate, onFailure)

    // RFC 9449 §8.2 nonce rotation: when nonces are enforced, every response
    // to a DPoP-scheme request carries a fresh `DPoP-Nonce` (unless one is
    // already set, e.g. by the use_dpop_nonce challenge). Rotating on success
    // keeps steady state at one round trip per call; rotating on failure hands
    // the client the nonce it needs to recover immediately — a proof rejected
    // after its nonce was consumed would otherwise cost two more round trips.
    dpopVerifier.flatMap(_.dpopNonceValidator) match {
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
                // The request itself already succeeded or failed on its own
                // merits; failing to mint its rotation nonce must not change
                // that. The client simply gets a challenge on its next call.
                validator.createNonce.attempt.map {
                  case Right(n) => resp.putHeaders(Header.Raw(DpopNonceHeader, n.value: String))
                  case Left(_)  => resp
                }
            }
          }
    }
  }

  private val DpopNonceHeader = ci"DPoP-Nonce"

  private def usesDpopScheme[F[_]](req: Request[F]): Boolean =
    tokenCredentials(req).flatten.exists(_._1.equalsIgnoreCase("DPoP"))

  /**
    * The request's `Authorization` credentials as `(scheme, token68)` — see
    * [[CredentialExtraction.tokenCredentialsOf]].
    */
  private[auth] def tokenCredentials[F[_]](
      req: Request[F]
  ): Option[Option[(String, String)]] =
    req.headers
      .get(Authorization.name)
      .map(_.head.value)
      .flatMap(CredentialExtraction.tokenCredentialsOf)

  /**
    * Require every scope in `required` on top of authentication. Compose per route group, e.g.
    * `requireScopes(Set("payments:write"))(paymentRoutes)`.
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

  /**
    * Require at least one of `roles` or `scopes`, e.g. `requireAny(roles = Set(PayrollAdmin), scopes
    * = Set(payroll.read))` for "PayrollAdmin OR payroll.read". A token that meets none of them is
    * valid but not allowed here: `403 insufficient_scope`, never `401`, so the client knows a new
    * token of the same kind will not help and does not retry.
    *
    * The challenge names the scopes only. Scopes are the OAuth vocabulary a client can request;
    * role names are internal and are not disclosed to callers.
    *
    * At least one role or scope is required: an empty policy would reject every request, which is
    * never what a route meant.
    */
  def requireAny[F[_]: Monad](
      roles: Set[Role] = Set.empty,
      scopes: Set[ScopeToken] = Set.empty,
      realm: String = "api"
  )(
      routes: AuthedRoutes[AuthContext, F]
  ): AuthedRoutes[AuthContext, F] = {
    require(roles.nonEmpty || scopes.nonEmpty, "requireAny needs at least one role or scope")
    Kleisli { req =>
      val ctx = req.context
      if (roles.exists(ctx.hasRole) || scopes.exists(ctx.hasScope)) routes(req)
      else
        OptionT.pure[F](
          errorResponse(AuthError.InsufficientScope(scopes.map(_.value)), realm, None)
        )
    }
  }

  /**
    * Keep a caller inside its own tenant. `tenantOf` names the tenant a request targets (usually
    * from the path, e.g. `/tenants/{tenant}/payroll`); the token's `tenant` claim must equal it, or
    * the answer is `403 access_denied`. A token without a `tenant` claim is refused on any
    * tenant-scoped request. When `tenantOf` returns `None` the request is not tenant-scoped and
    * passes.
    */
  def requireTenant[F[_]: Monad](
      tenantOf: AuthedRequest[F, AuthContext] => Option[String],
      realm: String = "api"
  )(routes: AuthedRoutes[AuthContext, F]): AuthedRoutes[AuthContext, F] =
    Kleisli { req =>
      tenantOf(req) match {
        case None                                                         => routes(req)
        case Some(target) if req.context.tenant.exists(_.value == target) => routes(req)
        case Some(_)                                                      => OptionT.pure[F](errorResponse(AuthError.AccessDenied, realm, None))
      }
    }

  /**
    * Level 2 authorization: ask the policy decision point whether this caller may perform `action`
    * on the resource `resourceOf` names (see [[authorization.AccessEvaluator]]).
    *
    *   - allowed: the routes run
    *   - denied: `403 access_denied`
    *   - the PDP cannot answer (unreachable, error, too slow): `503`, never a guess
    *
    * Put it inside the claim-based checks (`requireAny`, `requireScopes`, `requireTenant`), so a
    * request those already refuse costs no PDP call.
    */
  def requirePermission[F[_]: Sync](
      evaluator: authorization.AccessEvaluator[F],
      action: String,
      resourceOf: AuthedRequest[F, AuthContext] => authorization.AuthZen.Resource,
      realm: String = "api"
  )(routes: AuthedRoutes[AuthContext, F]): AuthedRoutes[AuthContext, F] =
    Kleisli { req =>
      val request = authorization.AuthZen.Request(
        subject = authorization.AuthZen.subjectOf(req.context),
        action = authorization.AuthZen.Action(action),
        resource = resourceOf(req)
      )
      OptionT(evaluator.evaluate(request).attempt.flatMap {
        case Right(true)  => routes(req).value
        case Right(false) => errorResponse[F](AuthError.AccessDenied, realm, None).some.pure[F]
        case Left(_)      =>
          errorResponse[F](AuthError.ValidationUnavailable, realm, None).some.pure[F]
      })
    }

  /**
    * Require that an end user is present on the token — i.e. reject machine-to-machine
    * (`client_credentials`) tokens on this route. Apply to endpoints that act on behalf of a
    * person; leave it off for service/batch endpoints, which are gated on `client_id` + scopes
    * instead.
    *
    * Failure is reported as `401 insufficient_user_authentication` (RFC 9470): the token is valid,
    * but the route requires a user and the token has none. `isUserPresent` defaults to
    * [[AuthContext.userPresent]]; override it with an authorization-server-specific signal if
    * needed.
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

  /**
    * Step-up authentication (RFC 9470): require that the user authenticated with one of the given
    * `acr` values. Takes at least one value (head + tail), so it can never be a silent no-op —
    * there is no empty-set form that admits everyone. On failure the client receives
    * `401 insufficient_user_authentication` with `acr_values`. For "any acr but recently
    * authenticated" use [[requireFreshAuth]]; compose the two for "this acr AND recent".
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

  /**
    * Step-up freshness (RFC 9470): require that the user authenticated within `maxAge` (via the
    * `auth_time` claim), regardless of `acr`. Since `auth_time` is a user-authentication claim,
    * this also implies a user is present. Compose with [[requireAcr]] for "this acr, authenticated
    * within `maxAge`". On failure the client receives `401 insufficient_user_authentication` with
    * `max_age`.
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

  /**
    * Adds an ACR step-up authorization check requiring `mfaAcr` (multi-factor auth; defaults to
    * `acr3`). Enforces authentication recency (default 5 minutes) per NIST SP 800-63B. Returns a
    * `WWW-Authenticate` challenge (`401 insufficient_user_authentication`) when step-up is
    * required.
    *
    * A convenience preset composing [[requireAcr]] over [[requireFreshAuth]]. Because the two gates
    * short-circuit independently, a token failing both receives the `acr_values` challenge first
    * and the `max_age` challenge on retry; if you need both in a single challenge, aggregate the
    * requirements instead.
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
    CredentialExtraction.extract(
      tokenInQuery = req.uri.query.pairs.exists(_._1 == "access_token"),
      authorization = req.headers.get(Authorization.name).fold(Nil)(_.toList.map(_.value)),
      dpopEnabled = dpopEnabled
    )

  private[auth] def errorResponse[F[_]](
      error: AuthError,
      realm: String,
      dpopAlgs: Option[String]
  ): Response[F] = {
    val challenge = AuthChallenge.of(error, realm, dpopAlgs)
    val base      = Response[F](Status.fromInt(challenge.status).getOrElse(Status.InternalServerError))
      .putHeaders(challenge.headers.map { case (name, value) =>
        Header.Raw(CIString(name), value)
      }*)
    challenge.jsonBody.fold(base) { json =>
      base.withEntity(json).withContentType(`Content-Type`(MediaType.application.json))
    }
  }

}
