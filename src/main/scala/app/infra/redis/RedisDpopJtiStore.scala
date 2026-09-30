package app.infra.redis

import scala.concurrent.duration.*

import cats.effect.syntax.temporal.*
import cats.effect.Temporal

import auth.dpop.DpopJtiStore
import sage.client.internal.Client
import sage.commands.{Commands, SetCondition, SetExpiry}

/**
  * A distributed DPoP proof `jti` single-use store ([[auth.dpop.DpopJtiStore]]) backed by
  * Redis/Valkey via Sage.
  *
  * A jti spent on one node is rejected on every node — the shared-store layer the FAPI 2.0 formal
  * analysis calls for behind a load balancer, and the complement to stateless nonces: a nonce is
  * reusable within its freshness window (Duende design), so only a cluster-wide single-use check on
  * the proof `jti` closes the in-window cross-node replay. Inject via
  * `DpopVerifier.default(..., jtiStore = Some(_))`.
  *
  * The check is one atomic `SET key "1" NX EX <ttl>`: with `NX` the write returns `false` when the
  * key already exists, i.e. the jti was already spent. The TTL is the verifier's retention (proof
  * max-age plus skew) plus a small `retentionMargin`, so entries self-evict and the key space never
  * grows without bound.
  *
  * The margin matters: the proof freshness check runs on the *app node's* clock while the TTL is
  * enforced by *Redis's* clock. Without slack, a jti entry could expire a hair before the proof
  * stops being accepted, leaving a razor-thin replay window.
  *
  * Every command is bounded by `timeout`: a stalled Redis surfaces as an error, which the verifier
  * turns into a fail-closed `503` rather than a hung request.
  */
object RedisDpopJtiStore {

  def apply[F[_]: Temporal](
      client: Client[F, String],
      timeout: FiniteDuration,
      prefix: String = "dpop:jti:",
      retentionMargin: FiniteDuration = 30.seconds
  ): DpopJtiStore[F] =
    new DpopJtiStore[F] {
      def markUsed(key: String, retention: FiniteDuration): F[Boolean] =
        client
          .run(
            Commands.set(
              prefix + key,
              "1",
              SetExpiry.In(retention + retentionMargin),
              SetCondition.IfNotExists
            )
          )
          .timeout(timeout)
    }

}
