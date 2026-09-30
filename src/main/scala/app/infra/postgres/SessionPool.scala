package app.infra.postgres

import scala.concurrent.duration.FiniteDuration

import cats.effect.{Ref, Resource, Temporal}
import cats.effect.std.Queue
import cats.effect.syntax.all.*
import cats.syntax.all.*

import skunk.Session

/**
  * A fixed set of long-lived Skunk sessions for the hot-path stores.
  *
  * Skunk's own pool resets a session every time it is returned (`UNLISTEN *`, `RESET ALL`), which
  * costs two extra round trips per call. The stores run a handful of fixed statements and never
  * change session state, so there is nothing to reset: here a session goes back into the queue as
  * it is.
  *
  * A session whose connection failed is replaced the next time its slot is taken, so a Postgres
  * restart costs the calls in flight at that moment, not the pool.
  *
  * Timeouts: every Skunk exchange is uncancelable (cancelling mid-exchange would leave the
  * connection out of step with the server), so a plain `timeout` would wait for a stalled statement
  * to finish. [[use]] waits at most `timeout` for a free session, then gives the statement the same
  * budget and stops waiting for it past that. The statement still owns its session until it ends,
  * which the sessions' `statement_timeout` bounds on the server side.
  */
final class SessionPool[F[_]] private (
    slots: Queue[F, SessionPool.Slot[F]],
    timeout: FiniteDuration
)(using F: Temporal[F]) {

  /**
    * Runs `f` on a free session, failing with a `TimeoutException` past the timeout.
    */
  def use[A](f: Session[F] => F[A]): F[A] =
    slots.take.timeout(timeout).flatMap { slot =>
      slot.session
        .flatMap(f)
        .guarantee(slots.offer(slot))
        .timeoutAndForget(timeout)
    }

}

object SessionPool {

  /**
    * One connection's place in the pool. Holds the open session with its finalizer, or nothing
    * after a failure until the next caller reconnects.
    */
  private[postgres] final class Slot[F[_]](
      connect: Resource[F, Session[F]],
      state: Ref[F, Option[(Session[F], F[Unit])]]
  )(using F: Temporal[F]) {

    def session: F[Session[F]] =
      state.get.flatMap {
        case Some((session, close)) =>
          session.isHealthy.ifM(
            F.pure(session),
            state.set(None) *> close.attempt *> reconnect
          )
        case None => reconnect
      }

    private def reconnect: F[Session[F]] =
      connect.allocated.flatMap(opened => state.set(Some(opened)).as(opened._1))

    def close: F[Unit] =
      state.getAndSet(None).flatMap(_.traverse_(_._2.attempt.void))

  }

  /**
    * Opens `size` sessions up front, so a database that cannot be reached fails the boot rather
    * than the first requests.
    */
  def resource[F[_]](
      connect: Resource[F, Session[F]],
      size: Int,
      timeout: FiniteDuration
  )(using F: Temporal[F]): Resource[F, SessionPool[F]] =
    for {
      slots <- Resource.eval(Queue.bounded[F, Slot[F]](size))
      _     <- List.fill(size)(()).parTraverse_ { _ =>
             Resource
               .make(
                 Ref.of[F, Option[(Session[F], F[Unit])]](None).map(new Slot(connect, _))
               )(_.close)
               .evalTap(slot => slot.session *> slots.offer(slot))
           }
    } yield new SessionPool(slots, timeout)

}
