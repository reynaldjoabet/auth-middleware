package auth
package dpop

import scala.concurrent.duration.FiniteDuration

import cats.effect.Sync

import com.github.benmanes.caffeine.cache.{Caffeine, Expiry}

/**
  * Single-use set for DPoP proof `jti`s (RFC 9449 §11.1) — the replay anchor.
  *
  * This replaces handing Nimbus a synchronous `SingleUseChecker`. Nimbus calls that interface from
  * inside proof verification, so a shared-store checker had to block a thread on the network round
  * trip; at high request rates that is a thread parked per in-flight DPoP request, and a stalled
  * store grows the blocking pool without bound. Here the check is an ordinary effect, run after
  * Nimbus has verified the proof, so a store round trip suspends a fiber instead of pinning a
  * thread.
  *
  * Order matters: the jti is spent only once the proof is otherwise valid, so a forged proof cannot
  * burn a legitimate client's jti.
  */
trait DpopJtiStore[F[_]] {

  /**
    * Atomically record `key` as spent for at least `retention`.
    *
    * @return
    *   `true` if this call spent it, `false` if it was already spent (a replay). A store failure is
    *   raised; the verifier fails closed on it.
    */
  def markUsed(key: String, retention: FiniteDuration): F[Boolean]
}

object DpopJtiStore {

  /**
    * Per-node, in-memory store — correct for a single node only. Behind a load balancer use a
    * shared store (see `app.infra.redis.RedisDpopJtiStore`), or a replay sent to a different node
    * is accepted.
    *
    * Entries expire after their own retention; there is deliberately no size bound, because
    * evicting a live entry early would reopen the replay window for that proof. Memory is bounded
    * instead by `request rate × retention` (~100 bytes per entry).
    */
  def inMemory[F[_]: Sync]: F[DpopJtiStore[F]] =
    Sync[F].delay {
      val spent = Caffeine
        .newBuilder()
        .expireAfter(new Expiry[String, java.lang.Long] {
          // The value is the retention in nanoseconds, so each entry carries its own TTL.
          def expireAfterCreate(key: String, ttlNanos: java.lang.Long, now: Long): Long =
            ttlNanos
          def expireAfterUpdate(
              key: String,
              ttlNanos: java.lang.Long,
              now: Long,
              currentDuration: Long
          ): Long = currentDuration
          def expireAfterRead(
              key: String,
              ttlNanos: java.lang.Long,
              now: Long,
              currentDuration: Long
          ): Long = currentDuration
        })
        .build[String, java.lang.Long]()
        .asMap()

      new DpopJtiStore[F] {
        def markUsed(key: String, retention: FiniteDuration): F[Boolean] =
          Sync[F].delay(spent.putIfAbsent(key, retention.toNanos) == null)
      }
    }

}
