package app.infra.redis

import scala.concurrent.duration.*

import auth.DpopNonce
import auth.dpop.DpopNonceStore
import cats.effect.Sync
import cats.syntax.all.*
import com.nimbusds.openid.connect.sdk.Nonce
import sage.client.internal.Client
import sage.commands.{Commands, SetExpiry}

/** A distributed [[auth.dpop.DpopNonceStore]] backed by Redis/Valkey via Sage,
  * for deployments whose threat model demands strictly single-use DPoP nonces
  * *across* nodes — a client's retry may land anywhere and a nonce still
  * verifies at most once cluster-wide. Wrap it with
  * [[auth.dpop.DpopNonceValidator.fromStore]].
  *
  * If freshness-window semantics are acceptable, prefer
  * [[auth.dpop.DpopNonceValidator.stateless]] (Duende's design) and skip the
  * shared store entirely.
  *
  * `mint` is `SET key "1" EX ttl`; `consume` is a single `DEL`, whose deleted
  * count makes check-and-consume atomic without scripting. Expiry is enforced
  * by the key TTL.
  */
final class RedisDpopNonceStore[F[_]: Sync](
    client: Client[F, String],
    ttl: FiniteDuration = 5.minutes,
    prefix: String = "dpop:nonce:"
) extends DpopNonceStore[F] {

  def mint: F[DpopNonce] =
    Sync[F].delay(new Nonce().getValue).flatMap { value =>
      client
        .run(Commands.set(prefix + value, "1", SetExpiry.In(ttl)))
        .as(DpopNonce.applyUnsafe(value))
    }

  def consume(presented: String): F[Boolean] =
    client.run(Commands.del(prefix + presented)).map(_ > 0L)
}
