package auth
package accesstoken

import java.net.URI

import cats.effect.IO

import auth.revocation.TokenDenylist
import munit.CatsEffectSuite
import org.typelevel.otel4s.metrics.Meter
import org.typelevel.otel4s.trace.Tracer

/**
  * Boot-time key fetching and the verified-token cache's metrics feed.
  */
class ValidatorLifecycleSpec extends CatsEffectSuite {

  import TestTokens.*

  private given Tracer[IO] = Tracer.noop[IO]

  test("the production validator refuses to start when the key set cannot be fetched") {
    // Nothing listens on port 1: the connection is refused at once.
    val unreachable = config.copy(jwksUri = URI.create("https://127.0.0.1:1/jwks"))
    AccessTokenValidator
      .default[IO](unreachable, AuthEvents.noop[IO], TokenDenylist.none[IO])
      .use_
      .attempt
      .map {
        case Left(e: IllegalStateException) =>
          assert(e.getMessage.contains("127.0.0.1:1/jwks"), e.getMessage)
        case other => fail(s"expected a boot failure, got $other")
      }
  }

  test("cache hits and misses are recorded for the lookups metric") {
    AuthTelemetry.otel[IO](Meter.noop[IO]).use { telemetry =>
      val validator = AccessTokenValidator.withKeySource[IO](
        config,
        keySource,
        AuthEvents.noop[IO],
        TokenDenylist.none[IO],
        None,
        telemetry
      )
      val token = sign(claims())
      (validator.validate(token) *> validator.validate(token) *> validator.validate(token)).map {
        _ =>
          val stats = telemetry.verifiedTokenCacheStats
            .getOrElse(fail("otel telemetry must expose cache stats"))
            .snapshot()
          assertEquals((stats.missCount, stats.hitCount), (1L, 2L))
      }
    }
  }

}
