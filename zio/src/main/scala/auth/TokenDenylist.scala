package auth

import java.util.concurrent.TimeoutException

import scala.concurrent.duration.FiniteDuration

import com.github.benmanes.caffeine.cache.Caffeine
import sage.backend.SageClient
import sage.commands.Commands
import zio.*

/**
  * Revocation check — the ZIO counterpart of the http4s service's `auth.revocation.TokenDenylist`.
  * A failure (raised error, including a timeout) means "cannot tell", and the validator fails
  * closed with `503`.
  */
trait TokenDenylist {
  def isRevoked(tokenId: String): Task[Boolean]
}

object TokenDenylist {

  val none: TokenDenylist = _ => ZIO.succeed(false)

  /**
    * `EXISTS prefix+jti` on Redis/Valkey, bounded by `timeout`. Same keys as the http4s service's
    * `RedisTokenDenylist`, so both services read the same revocations.
    */
  def redis(
      client: SageClient,
      timeout: FiniteDuration,
      prefix: String = "revoked:jti:"
  ): TokenDenylist =
    tokenId =>
      client
        .run(Commands.exists(prefix + tokenId))
        .map(_ > 0L)
        .timeoutFail(new TimeoutException(s"revocation lookup exceeded $timeout"))(
          Duration.fromScala(timeout)
        )

  /**
    * Per-node read-through cache, with the semantics of `auth.revocation.TokenDenylist.cached` in
    * the http4s service: an answer is reused for `ttl` (the worst-case revocation delay it adds),
    * and errors are never cached.
    */
  def cached(
      underlying: TokenDenylist,
      ttl: FiniteDuration,
      maxEntries: Long
  ): TokenDenylist = {
    val answers = Caffeine
      .newBuilder()
      .expireAfterWrite(java.time.Duration.ofNanos(ttl.toNanos))
      .maximumSize(maxEntries)
      .build[String, java.lang.Boolean]()
    tokenId =>
      ZIO.suspendSucceed(Option(answers.getIfPresent(tokenId)) match {
        case Some(revoked) => ZIO.succeed(revoked.booleanValue)
        case None          =>
          underlying.isRevoked(tokenId).tap(revoked => ZIO.succeed(answers.put(tokenId, revoked)))
      })
  }

}
