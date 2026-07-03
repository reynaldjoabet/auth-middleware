package auth
import auth.dpop.{DpopConfig, DpopNonceValidator, DpopVerifier}
import auth.revocation.TokenDenylist

import cats.effect.IO
import cats.effect.kernel.Resource
import io.github.iltotore.iron.*
import munit.CatsEffectSuite
import org.http4s.AuthedRoutes
import org.http4s.HttpApp
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.dsl.Http4sDsl
import org.http4s.implicits.*
import org.typelevel.ci.*

/** Shared fixtures for the DPoP suites: a validator over the test JWKS, a
  * trivial protected route, and helpers to build DPoP requests and read
  * challenge headers. [[DpopVerifierSpec]], [[DpopNonceValidatorSpec]] and
  * [[DpopNonceStoreSpec]] extend this, mirroring the split between
  * `DpopVerifier`, `DpopNonceValidator` and `DpopNonceStore`.
  */
abstract class DpopBaseSuite extends CatsEffectSuite {
  import TestTokens.*

  protected object dsl extends Http4sDsl[IO]
  import dsl.*

  protected val accountsUri = uri"https://api.test.example/accounts"

  protected val validator: JwtValidator[IO] =
    JwtValidator.fromKeySource[IO](
      config,
      keySource,
      AuthEvents.noop[IO],
      TokenDenylist.none[IO]
    )

  protected val routes: AuthedRoutes[AuthContext, IO] = AuthedRoutes.of {
    case GET -> Root / "accounts" as ctx => Ok(ctx.subject.value: String)
  }

  /** The middleware stack under test. `nonces` switches on RFC 9449 §8-9
    * server-provided nonce enforcement.
    */
  protected def app(
      policy: SenderConstraintPolicy = SenderConstraintPolicy.EnforceWhenBound,
      nonces: Option[DpopNonceValidator[IO]] = None
  ): Resource[IO, HttpApp[IO]] =
    DpopVerifier
      .default[IO](DpopConfig(), AuthEvents.noop[IO], nonces = nonces)
      .map { verifier =>
        BearerAuth
          .middleware(
            validator,
            AuthEvents.noop[IO],
            senderConstraint = policy,
            dpop = Some(verifier)
          )
          .apply(routes)
          .orNotFound
      }

  protected def appWithNonces: Resource[IO, HttpApp[IO]] =
    Resource
      .eval(DpopNonceValidator.inMemory[IO]())
      .flatMap(store => app(nonces = Some(store)))

  protected def dpopRequest(token: String, proof: String): Request[IO] =
    Request[IO](Method.GET, accountsUri)
      .putHeaders(
        org.http4s.Header.Raw(ci"Authorization", s"DPoP $token"),
        org.http4s.Header.Raw(ci"DPoP", proof)
      )

  protected def bearerRequest(token: String): Request[IO] =
    Request[IO](Method.GET, accountsUri)
      .putHeaders(org.http4s.Header.Raw(ci"Authorization", s"Bearer $token"))

  protected def challengeOf(resp: Response[IO]): String =
    resp.headers.get(ci"WWW-Authenticate").map(_.head.value).getOrElse("")

  protected def nonceOf(resp: Response[IO]): String =
    resp.headers.get(ci"DPoP-Nonce").map(_.head.value).getOrElse("")
}
