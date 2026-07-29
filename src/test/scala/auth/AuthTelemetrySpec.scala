package auth

import cats.effect.IO
import cats.syntax.all.*
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.{JWK, JWKSelector}
import com.nimbusds.jose.proc.SecurityContext
import munit.CatsEffectSuite
import org.typelevel.otel4s.metrics.Meter
import org.typelevel.otel4s.trace.Tracer

import auth.accesstoken.AccessTokenValidator
import auth.revocation.{TokenDenylist, TokenIntrospection}

/** Instrumentation must be observationally invisible: same values, same errors,
  * same failure modes. A telemetry decorator that swallowed a denylist error or
  * changed an [[AuthError]] would turn an observability feature into a security
  * bug, so every port is checked through the instrumented path.
  *
  * `Meter.noop` and `Tracer.noop` keep the assertions on behaviour rather than
  * on emitted measurements — recording is otel4s's job, not this codebase's.
  */
class AuthTelemetrySpec extends CatsEffectSuite {

  import TestTokens.*

  private given Tracer[IO] = Tracer.noop[IO]

  private def instrumented[A](use: AuthTelemetry[IO] => IO[A]): IO[A] =
    AuthTelemetry.otel[IO](Meter.noop[IO]).use(use)

  test("an accepted token is still accepted, with its claims intact") {
    instrumented { telemetry =>
      AccessTokenValidator
        .withKeySource[IO](
          config,
          keySource,
          AuthEvents.noop[IO],
          TokenDenylist.none[IO],
          None,
          telemetry
        )
        .validate(sign(claims()))
        .map { result =>
          val ctx = result.fold(
            error => fail(s"expected success, got $error"),
            identity
          )
          assertEquals(ctx.subject.value: String, "user-123")
        }
    }
  }

  test("an unreachable key source still fails closed, unchanged") {
    val downSource = new JWKSource[SecurityContext] {
      def get(
          selector: JWKSelector,
          ctx: SecurityContext
      ): java.util.List[JWK] =
        throw new KeySourceException("JWKS endpoint unreachable")
    }
    instrumented { telemetry =>
      AccessTokenValidator
        .withKeySource[IO](
          config,
          downSource,
          AuthEvents.noop[IO],
          TokenDenylist.none[IO],
          None,
          telemetry
        )
        .validate(sign(claims()))
        .map(result =>
          assertEquals(result, Left(AuthError.ValidationUnavailable))
        )
    }
  }

  test("denylist answers pass through in both directions") {
    def fixed(revoked: Boolean): TokenDenylist[IO] = new TokenDenylist[IO] {
      def isRevoked(tokenId: String): IO[Boolean] = IO.pure(revoked)
    }
    instrumented { telemetry =>
      for {
        yes <- telemetry.instrumentDenylist(fixed(true)).isRevoked("jti")
        no <- telemetry.instrumentDenylist(fixed(false)).isRevoked("jti")
      } yield {
        assert(yes)
        assert(!no)
      }
    }
  }

  test("a denylist failure is re-raised, not swallowed into `not revoked`") {
    val outage = new RuntimeException("redis unreachable")
    val broken = new TokenDenylist[IO] {
      def isRevoked(tokenId: String): IO[Boolean] = IO.raiseError(outage)
    }
    instrumented { telemetry =>
      telemetry
        .instrumentDenylist(broken)
        .isRevoked("jti")
        .attempt
        .map(result => assertEquals(result, Left(outage)))
    }
  }

  test("every introspection result passes through") {
    def fixed(result: TokenIntrospection.Result): TokenIntrospection[IO] =
      new TokenIntrospection[IO] {
        def check(rawToken: String): IO[TokenIntrospection.Result] =
          IO.pure(result)
      }
    instrumented { telemetry =>
      List(
        TokenIntrospection.Result.Active,
        TokenIntrospection.Result.Inactive,
        TokenIntrospection.Result.Unavailable
      ).traverse_(expected =>
        telemetry
          .instrumentIntrospection(fixed(expected))
          .check("token")
          .map(actual => assertEquals(actual, expected))
      )
    }
  }

  test("noop hands every port back untouched") {
    val telemetry = AuthTelemetry.noop[IO]
    val denylist = TokenDenylist.none[IO]
    assert(telemetry.instrumentDenylist(denylist) eq denylist)
  }
}
