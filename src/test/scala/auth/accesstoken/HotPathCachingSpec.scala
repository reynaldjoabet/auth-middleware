package auth
package accesstoken

import java.util.concurrent.atomic.AtomicInteger

import scala.concurrent.duration.*

import cats.effect.IO

import auth.revocation.TokenDenylist
import com.nimbusds.jose.jwk.{JWK, JWKSelector}
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import munit.CatsEffectSuite

/**
  * The per-node caches on the validation hot path: verified tokens skip signature checks without
  * changing any decision, and the revocation cache trades a bounded revocation delay for store
  * load. Also the fail-closed contract for an unreachable denylist.
  */
class HotPathCachingSpec extends CatsEffectSuite {

  import TestTokens.*

  /**
    * Counts key lookups — one per signature verification, so a cache hit shows up as no call.
    */
  private final class CountingKeySource extends JWKSource[SecurityContext] {

    val calls = new AtomicInteger(0)

    def get(selector: JWKSelector, context: SecurityContext): java.util.List[JWK] = {
      val _ = calls.incrementAndGet()
      keySource.get(selector, context)
    }

  }

  /**
    * A denylist whose answer can be flipped, counting lookups.
    */
  private final class MutableDenylist extends TokenDenylist[IO] {

    @volatile var revoked: Set[String] = Set.empty
    val calls                          = new AtomicInteger(0)

    def isRevoked(tokenId: String): IO[Boolean] =
      IO { val _ = calls.incrementAndGet(); revoked.contains(tokenId) }

  }

  private def validator(
      keys: JWKSource[SecurityContext],
      denylist: TokenDenylist[IO] = TokenDenylist.none[IO],
      cfg: AccessTokenConfig = config
  ): AccessTokenValidator[IO] =
    AccessTokenValidator.withKeySource[IO](cfg, keys, AuthEvents.noop[IO], denylist)

  test("a reused token is verified once, then served from the cache") {
    val keys  = new CountingKeySource
    val v     = validator(keys)
    val token = sign(claims())
    for {
      first  <- v.validate(token)
      second <- v.validate(token)
    } yield {
      assert(first.isRight, first)
      assertEquals(second.map(_.subject), first.map(_.subject))
      assertEquals(keys.calls.get, 1)
    }
  }

  test("verifiedTokenCacheMaxEntries = 0 verifies every time") {
    val keys  = new CountingKeySource
    val v     = validator(keys, cfg = config.copy(verifiedTokenCacheMaxEntries = 0L))
    val token = sign(claims())
    (v.validate(token) *> v.validate(token)).map(_ => assertEquals(keys.calls.get, 2))
  }

  test("a failed verification is never cached") {
    val keys   = new CountingKeySource
    val v      = validator(keys)
    val forged = sign(claims(), key = rogueKey)
    for {
      first  <- v.validate(forged)
      second <- v.validate(forged)
    } yield {
      assertEquals(first, Left(AuthError.InvalidToken.Rejected))
      assertEquals(second, Left(AuthError.InvalidToken.Rejected))
      assertEquals(keys.calls.get, 2)
    }
  }

  test("the denylist still runs on a cache hit: revocation is not bypassed") {
    val denylist = new MutableDenylist
    val v        = validator(new CountingKeySource, denylist)
    val token    = sign(claims(jti = Some("jti-revoke-me")))
    for {
      before <- v.validate(token)
      _       = denylist.revoked = Set("jti-revoke-me")
      after  <- v.validate(token)
    } yield {
      assert(before.isRight, before)
      assertEquals(after, Left(AuthError.InvalidToken.Revoked))
    }
  }

  test("an unreachable denylist fails closed as ValidationUnavailable, not a 500") {
    val down = new TokenDenylist[IO] {
      def isRevoked(tokenId: String): IO[Boolean] =
        IO.raiseError(new java.util.concurrent.TimeoutException("redis stalled"))
    }
    validator(new CountingKeySource, down)
      .validate(sign(claims()))
      .map(result => assertEquals(result, Left(AuthError.ValidationUnavailable)))
  }

  test("TokenDenylist.cached reuses an answer within its ttl") {
    val underlying = new MutableDenylist
    for {
      cached <- TokenDenylist.cached(underlying, ttl = 1.minute, maxEntries = 100L)
      a      <- cached.isRevoked("jti-1")
      b      <- cached.isRevoked("jti-1")
    } yield {
      assertEquals((a, b), (false, false))
      assertEquals(underlying.calls.get, 1)
    }
  }

  test("TokenDenylist.cached asks again once the ttl has passed") {
    val underlying = new MutableDenylist
    for {
      cached <- TokenDenylist.cached(underlying, ttl = 50.millis, maxEntries = 100L)
      before <- cached.isRevoked("jti-1")
      _       = underlying.revoked = Set("jti-1")
      _      <- IO.sleep(100.millis)
      after  <- cached.isRevoked("jti-1")
    } yield assertEquals((before, after), (false, true))
  }

  test("TokenDenylist.cached never caches a store failure") {
    val calls = new AtomicInteger(0)
    val flaky = new TokenDenylist[IO] {
      def isRevoked(tokenId: String): IO[Boolean] =
        IO(calls.incrementAndGet()).flatMap(n =>
          if (n == 1) IO.raiseError(new RuntimeException("blip")) else IO.pure(false)
        )
    }
    for {
      cached <- TokenDenylist.cached(flaky, ttl = 1.minute, maxEntries = 100L)
      first  <- cached.isRevoked("jti-1").attempt
      second <- cached.isRevoked("jti-1")
    } yield {
      assert(first.isLeft)
      assertEquals(second, false)
      assertEquals(calls.get, 2)
    }
  }

}
