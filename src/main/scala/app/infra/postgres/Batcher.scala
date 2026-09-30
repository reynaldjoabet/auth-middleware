package app.infra.postgres

import java.util.concurrent.RejectedExecutionException

import scala.concurrent.duration.FiniteDuration

import cats.effect.{Deferred, Resource, Temporal}
import cats.effect.std.Queue
import cats.effect.syntax.all.*
import cats.syntax.all.*

import skunk.Session

/**
  * Runs concurrent calls of one kind as a single statement.
  *
  * Most of a store call's cost is per statement, not per key: the round trip, a pass through the
  * executor, a transaction. So callers queue their key, and a worker that gets a session takes
  * every key waiting at that moment (up to `maxBatch`) and answers them all with one statement.
  *
  * Nothing waits for a batch to fill. A worker takes the first key as soon as it arrives and the
  * rest only once it holds a session, so at low load a batch is one key and costs what a plain call
  * does. Batches grow only when calls arrive faster than statements finish, and that is exactly
  * when merging them pays.
  *
  * Fails closed like the direct calls: a full queue is rejected at once, a caller waits at most
  * `timeout`, and a failed statement fails every call in its batch.
  *
  * @param run
  *   answers a batch on one session, one result per key and in the same order
  */
final class Batcher[F[_], K, V] private (
    queue: Queue[F, Batcher.Pending[F, K, V]],
    timeout: FiniteDuration
)(using F: Temporal[F]) {

  def apply(key: K): F[V] =
    Deferred[F, Either[Throwable, V]].flatMap { result =>
      queue.tryOffer(Batcher.Pending(key, result)).flatMap {
        case true  => result.get.rethrow.timeout(timeout)
        case false => F.raiseError(new RejectedExecutionException("store batch queue is full"))
      }
    }

}

object Batcher {

  private[postgres] final case class Pending[F[_], K, V](
      key: K,
      result: Deferred[F, Either[Throwable, V]]
  )

  /**
    * @param workers
    *   statements of this kind in flight at once; each needs a session from `pool`
    * @param capacity
    *   calls that may wait; past it a call fails at once instead of queueing behind a stalled
    *   database
    */
  def resource[F[_], K, V](
      pool: SessionPool[F],
      workers: Int,
      maxBatch: Int,
      capacity: Int,
      timeout: FiniteDuration
  )(
      run: (Session[F], List[K]) => F[List[V]]
  )(using F: Temporal[F]): Resource[F, Batcher[F, K, V]] = {

    def answer(batch: List[Pending[F, K, V]], outcome: Either[Throwable, List[V]]): F[Unit] =
      outcome match {
        case Right(values) if values.sizeCompare(batch) == 0 =>
          batch.zip(values).traverse_((pending, value) => pending.result.complete(Right(value)))
        case Right(values) =>
          val error = new IllegalStateException(
            s"a batch of ${batch.size} keys produced ${values.size} results"
          )
          batch.traverse_(_.result.complete(Left(error)))
        case Left(error) => batch.traverse_(_.result.complete(Left(error)))
      }

    def worker(queue: Queue[F, Pending[F, K, V]]): F[Unit] =
      queue.take.flatMap { first =>
        pool
          .use { session =>
            // Keys that arrived while this worker waited for a session join now.
            val more = if (maxBatch > 1) queue.tryTakeN(Some(maxBatch - 1)) else F.pure(Nil)
            more.flatMap { rest =>
              val batch = first :: rest
              run(session, batch.map(_.key)).attempt.flatMap(answer(batch, _))
            }
          }
          // No session in time: `first` fails (`complete` ignores a second
          // answer, so this never overrides one already given).
          .handleErrorWith(error => first.result.complete(Left(error)).void)
      }.foreverM

    for {
      queue <- Resource.eval(Queue.bounded[F, Pending[F, K, V]](capacity))
      _     <- List.fill(workers)(worker(queue).background).sequence_
    } yield new Batcher(queue, timeout)
  }

}
