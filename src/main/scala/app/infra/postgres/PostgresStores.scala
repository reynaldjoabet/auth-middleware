package app.infra.postgres

import scala.concurrent.duration.*

import cats.effect.{Async, Resource}
import cats.effect.std.Console
import cats.effect.syntax.spawn.*
import cats.syntax.all.*
import cats.Functor
import fs2.io.net.Network

import auth.dpop.{DpopJtiStore, DpopNonceStore}
import auth.revocation.TokenDenylist
import auth.DpopNonce
import app.config.{DbConfig, PostgresStoreSettings}
import app.infra.SharedStores
import com.nimbusds.openid.connect.sdk.Nonce
import org.slf4j.LoggerFactory
import org.typelevel.otel4s.metrics.MeterProvider
import org.typelevel.otel4s.trace.TracerProvider
import skunk.*
import skunk.codec.all.*
import skunk.data.{Arr, Completion}
import skunk.implicits.*

/**
  * The shared auth state in Postgres, through Skunk: the counterparts of
  * `app.infra.redis.{RedisTokenDenylist, RedisDpopJtiStore, RedisDpopNonceStore}`, over the tables
  * of migration `V2__shared_auth_state.sql`.
  *
  * Concurrent calls of one kind are answered by a single statement ([[Batcher]]), with the keys
  * passed as arrays:
  *
  *   - revocation check: `SELECT jti … WHERE jti = ANY($1) AND expires_at > now()`
  *   - spend proof `jti`s: `INSERT … SELECT … unnest($1, $2) ON CONFLICT DO UPDATE … WHERE expired
  *     RETURNING jti`. The `jti`s that come back were spent by this statement; the others were
  *     already spent. Atomic per key, like `SET NX`.
  *   - consume nonces: `DELETE … WHERE nonce = ANY($1) AND expires_at > now() RETURNING nonce`
  *   - mint nonces: `INSERT … SELECT … unnest($1)`
  *
  * A key that appears twice in one batch is answered as two calls in a row would be: the first
  * spends or consumes it, the second finds it gone. Keys are written in sorted order, so two
  * statements inserting overlapping keys lock them in the same order and cannot deadlock.
  *
  * Expiry is part of every predicate, so an expired row reads as absent even before the sweeper
  * deletes it. Times come from the database clock alone (`now()`), never mixed with a node's.
  *
  * Calls fail closed: a timeout or a database error is raised, and the verifier answers `503`.
  */
object PostgresStores {

  private val log = LoggerFactory.getLogger(getClass)

  /**
    * Calls allowed to wait for a batch, per kind of call. Past it a call fails at once.
    */
  private val QueueCapacity = 16_384

  /**
    * The three stores on one [[SessionPool]], with the expired-row sweeper running in the
    * background.
    */
  def resource[F[_]: Async: Network: Console](
      db: DbConfig,
      settings: PostgresStoreSettings
  ): Resource[F, SharedStores[F]] =
    for {
      pool <- SessionPool.resource[F](
                session(db, settings),
                settings.sessions,
                settings.commandTimeout
              )
      stores <- Stores.resource(pool, settings)
      // Its own session and deadline: under load the hot path keeps every
      // pooled session busy, and a sweep must not fail for want of one (or
      // take one from a request).
      sweeping <- SessionPool.resource[F](
                    session(db, settings.copy(commandTimeout = Sweeper.Timeout)),
                    size = 1,
                    Sweeper.Timeout
                  )
      _ <- Sweeper(sweeping, settings).background
    } yield SharedStores(stores.denylist, stores.jtis, stores.nonces)

  /**
    * One store session. `statement_timeout` makes Postgres abandon a statement the caller has
    * already given up on, which frees the session: see [[SessionPool]].
    */
  def session[F[_]: Async: Network: Console](
      db: DbConfig,
      settings: PostgresStoreSettings
  ): Resource[F, Session[F]] = {
    // Skunk traces and meters every statement; the stores already report
    // their latency through AuthTelemetry, so its instrumentation stays off.
    given TracerProvider[F] = TracerProvider.noop[F]
    given MeterProvider[F]  = MeterProvider.noop[F]
    Session
      .Builder[F]
      .withHost(db.host)
      .withPort(db.port)
      .withUserAndPassword(db.user, db.password.value)
      .withDatabase(db.name)
      .withConnectionParameters(
        Session.DefaultConnectionParameters ++ Map(
          "application_name"   -> "auth-middleware-store",
          "statement_timeout"  -> settings.commandTimeout.toMillis.toString,
          "synchronous_commit" -> (if (settings.synchronousCommit) "on" else "off")
        )
      )
      .single
  }

  // --- statements -----------------------------------------------------------

  private val revokedAmong: Query[Arr[String], String] =
    sql"""SELECT jti FROM auth.revoked_tokens
          WHERE jti = ANY($_text) AND expires_at > now()""".query(text)

  private val revoke: Command[(String, Long)] =
    sql"""INSERT INTO auth.revoked_tokens (jti, expires_at)
          VALUES ($text, now() + $int8 * interval '1 millisecond')
          ON CONFLICT (jti) DO UPDATE
            SET expires_at = GREATEST(auth.revoked_tokens.expires_at, EXCLUDED.expires_at)""".command

  // An expired row is taken over rather than blocking the insert, so a jti
  // that is spent again after its retention reads the same as a fresh one.
  private val spendJtis: Query[(Arr[String], Arr[Long]), String] =
    sql"""INSERT INTO auth.dpop_spent_jtis (jti, expires_at)
          SELECT k, now() + ms * interval '1 millisecond'
          FROM unnest($_text, $_int8) AS t(k, ms)
          ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at
            WHERE auth.dpop_spent_jtis.expires_at <= now()
          RETURNING jti""".query(text)

  private val mintNonces: Command[(Arr[String], Arr[Long])] =
    sql"""INSERT INTO auth.dpop_nonces (nonce, expires_at)
          SELECT n, now() + ms * interval '1 millisecond'
          FROM unnest($_text, $_int8) AS t(n, ms)""".command

  private val consumeNonces: Query[Arr[String], String] =
    sql"""DELETE FROM auth.dpop_nonces
          WHERE nonce = ANY($_text) AND expires_at > now()
          RETURNING nonce""".query(text)

  /**
    * Answers each key in order: `true` for the first occurrence of a key in `hits`, `false` for any
    * repeat and for keys not in `hits`.
    */
  private def firstOccurrences(keys: List[String], hits: List[String]): List[Boolean] = {
    val remaining = scala.collection.mutable.HashSet.from(hits)
    keys.map(remaining.remove)
  }

  /**
    * One batch's keys, each once, in sorted order (the lock order), with the longest requested
    * lifetime when a key repeats.
    */
  private def sortedDistinct(items: List[(String, FiniteDuration)]): (Arr[String], Arr[Long]) = {
    val longest = items.groupMapReduce(_._1)(_._2.toMillis)(math.max).toList.sortBy(_._1)
    (Arr.fromFoldable(longest.map(_._1)), Arr.fromFoldable(longest.map(_._2)))
  }

  // --- stores ---------------------------------------------------------------

  /**
    * The stores over an existing pool; [[resource]] adds the pool and the sweeper.
    *
    * @param retentionMargin
    *   added to every spent `jti`'s retention; the same part it plays in `RedisDpopJtiStore`
    */
  final case class Stores[F[_]](
      denylist: PostgresTokenDenylist[F],
      jtis: DpopJtiStore[F],
      nonces: FiniteDuration => DpopNonceStore[F]
  )

  object Stores {

    def resource[F[_]: Async](
        pool: SessionPool[F],
        settings: PostgresStoreSettings,
        retentionMargin: FiniteDuration = 30.seconds
    ): Resource[F, Stores[F]] = {
      def batcher[K, V](run: (Session[F], List[K]) => F[List[V]]) =
        Batcher.resource[F, K, V](
          pool,
          workers = settings.sessions,
          maxBatch = settings.maxBatch,
          capacity = QueueCapacity,
          timeout = settings.commandTimeout
        )(run)

      for {
        revoked <- batcher[String, Boolean] { (session, jtis) =>
                     session.execute(revokedAmong)(Arr.fromFoldable(jtis.distinct)).map { hits =>
                       val revoked = hits.toSet
                       jtis.map(revoked.contains)
                     }
                   }
        spent <- batcher[(String, FiniteDuration), Boolean] { (session, items) =>
                   session
                     .execute(spendJtis)(sortedDistinct(items))
                     .map(firstOccurrences(items.map(_._1), _))
                 }
        minted <- batcher[(String, FiniteDuration), Unit] { (session, items) =>
                    session.execute(mintNonces)(sortedDistinct(items)).as(items.as(()))
                  }
        consumed <- batcher[String, Boolean] { (session, nonces) =>
                      session
                        .execute(consumeNonces)(Arr.fromFoldable(nonces.distinct.sorted))
                        .map(firstOccurrences(nonces, _))
                    }
      } yield Stores(
        new PostgresTokenDenylist[F](revoked, pool),
        new DpopJtiStore[F] {
          def markUsed(key: String, retention: FiniteDuration): F[Boolean] =
            spent((key, retention + retentionMargin))
        },
        ttl =>
          new DpopNonceStore[F] {
            def mint: F[DpopNonce] =
              Async[F].delay(new Nonce().getValue).flatMap { value =>
                minted((value, ttl)).as(DpopNonce.applyUnsafe(value))
              }
            def consume(presented: String): F[Boolean] = consumed(presented)
          }
      )
    }

  }

  /**
    * Revocation denylist. Front it with [[auth.revocation.TokenDenylist.cached]], as with Redis.
    */
  final class PostgresTokenDenylist[F[_]: Functor] private[postgres] (
      revoked: Batcher[F, String, Boolean],
      pool: SessionPool[F]
  ) extends TokenDenylist[F] {

    def isRevoked(tokenId: String): F[Boolean] = revoked(tokenId)

    /**
      * Revoke a token until it would have expired (`ttl` = `exp - now`). Revoking again never
      * shortens an existing entry. Not batched: revocations are rare, and each should commit on its
      * own.
      */
    def revoke(tokenId: String, ttl: FiniteDuration): F[Unit] =
      pool.use(_.execute(PostgresStores.revoke)((tokenId, ttl.toMillis))).void

  }

  // --- sweeper --------------------------------------------------------------

  private[postgres] object Sweeper {

    /**
      * Budget for one sweep statement, on the sweeper's own session.
      */
    val Timeout: FiniteDuration = 10.seconds

    private val tables = List("auth.revoked_tokens", "auth.dpop_spent_jtis", "auth.dpop_nonces")

    private def keyOf(table: String): String =
      if (table == "auth.dpop_nonces") "nonce" else "jti"

    // SKIP LOCKED: nodes sweeping at the same moment take different rows
    // instead of queueing behind each other.
    private def deleteExpired(table: String): Command[Int] = {
      val key = keyOf(table)
      sql"""DELETE FROM #$table WHERE #$key IN (
              SELECT #$key FROM #$table WHERE expires_at <= now()
              LIMIT $int4 FOR UPDATE SKIP LOCKED
            )""".command
    }

    /**
      * Deletes expired rows every `sweepInterval`, in batches until a batch comes back short. A
      * failure is logged and the next round tries again: expired rows are already ignored by every
      * read, so a missed sweep costs space, not correctness.
      */
    def apply[F[_]: Async](pool: SessionPool[F], settings: PostgresStoreSettings): F[Unit] = {
      val batch = settings.sweepBatch: Int

      def drain(statement: Command[Int]): F[Long] =
        pool.use(_.execute(statement)(batch)).flatMap {
          case Completion.Delete(n) if n >= batch => drain(statement).map(_ + n)
          case Completion.Delete(n)               => Async[F].pure(n.toLong)
          case _                                  => Async[F].pure(0L)
        }

      val round =
        tables.traverse_ { table =>
          drain(deleteExpired(table)).attempt.flatMap {
            case Right(0L) => Async[F].unit
            case Right(n)  => Async[F].delay(log.debug("Swept {} expired rows from {}", n, table))
            case Left(e)   =>
              Async[F].delay(log.warn(s"Sweeping $table failed; retrying next round", e))
          }
        }

      (Async[F].sleep(settings.sweepInterval) *> round).foreverM
    }

  }

}
