package app.http

import cats.data.Kleisli
import cats.effect.std.Semaphore
import cats.effect.Concurrent
import cats.syntax.all.*

import org.http4s.{Header, HttpApp, Response, Status}
import org.typelevel.ci.*

/**
  * Caps the number of requests in flight on this node and rejects the excess immediately with `503`
  * + `Retry-After`.
  *
  * Without a cap, overload shows up as queueing: every request slows down, clients time out and
  * retry, and the extra load keeps the node saturated long after the spike. With one, the node
  * keeps serving `maxInFlight` requests at normal latency and the load balancer (or client) moves
  * the rest elsewhere, which is the behaviour a fleet needs to degrade gracefully.
  *
  * Size `maxInFlight` from a load test: by Little's law, in-flight ≈ throughput × latency, so a
  * node doing 50k req/s at 2 ms holds ~100. Set the cap a few times above the healthy steady state.
  *
  * Probe paths are exempt: a node that is busy is not dead, and failing liveness under load would
  * make the orchestrator restart healthy nodes exactly when capacity is scarcest.
  *
  * The permit covers producing the response, not streaming its body; fine for the small bodies an
  * auth-fronted API returns.
  */
object LoadShedding {

  def httpApp[F[_]: Concurrent](
      maxInFlight: Int,
      exemptPaths: Set[String],
      onShed: F[Unit]
  )(app: HttpApp[F]): F[HttpApp[F]] =
    Semaphore[F](maxInFlight.toLong).map { permits =>
      Kleisli { request =>
        if (exemptPaths.contains(request.uri.path.renderString)) app(request)
        else
          permits.tryPermit.use {
            case true  => app(request)
            case false => onShed.as(overloaded[F])
          }
      }
    }

  private def overloaded[F[_]]: Response[F] =
    Response[F](Status.ServiceUnavailable).putHeaders(
      Header.Raw(ci"Retry-After", "1"),
      Header.Raw(ci"Cache-Control", "no-store")
    )

}
