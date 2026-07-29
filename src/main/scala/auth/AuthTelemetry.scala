package auth

import java.net.URL
import java.util.concurrent.TimeUnit

import scala.concurrent.duration.FiniteDuration

import cats.effect.std.Dispatcher
import cats.effect.{Async, Clock, Resource}
import cats.syntax.all.*
import com.nimbusds.jose.jwk.source.{
  CachingJWKSetSource,
  OutageTolerantJWKSetSource,
  RetryingJWKSetSource
}
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.events.{Event, EventListener}
import com.nimbusds.jose.util.{Resource as JoseResource, ResourceRetriever}
import org.typelevel.otel4s.Attribute
import org.typelevel.otel4s.metrics.{
  BucketBoundaries,
  Counter,
  Histogram,
  Meter
}
import org.typelevel.otel4s.trace.{Span, StatusCode, Tracer}

import auth.accesstoken.AccessTokenValidator
import auth.revocation.{TokenDenylist, TokenIntrospection}

/** Latency and dependency-health instrumentation for the authentication path.
  *
  * [[AuthEvents]] answers *what was decided* — it counts outcomes. This answers
  * *what it cost and which dependency was responsible*, which is the other half
  * of an on-call story: counters tell you tokens are being rejected, timings
  * tell you the JWKS endpoint went from 4 ms to 4 s and took the API's p99 with
  * it. Neither is derivable from the other.
  *
  * Every measurement is a decorator around an existing port, so instrumentation
  * is opt-in at the composition root and [[noop]] leaves the hot path
  * byte-for-byte as it was.
  *
  * ==Instruments==
  *
  *   - `auth.validation.duration` — end-to-end token validation, attributed by
  *     the same stable outcome code [[AuthEvents]] uses, so a latency spike can
  *     be split by *why* (a slow `success` is a JWKS problem; a slow
  *     `invalid_token` is not)
  *   - `auth.denylist.duration` — the Redis `EXISTS` on the hot path, labelled
  *     `revoked` / `allowed` / `error`. The `error` series is the one to alert
  *     on: a denylist failure currently propagates as a 500, and without this
  *     instrument a Redis outage is invisible until users complain
  *   - `auth.introspection.duration` — the RFC 7662 network hop, labelled
  *     `active` / `inactive` / `unavailable`
  *   - `auth.jwks.fetch.duration` — time inside Nimbus's HTTP fetch of the JWKS
  *   - `auth.jwks.events` — Nimbus's own cache lifecycle: refresh initiated /
  *     completed / timed out, threads waiting on a refresh, retrials, and
  *     outage-tolerant serving of a stale key set. An outage-tolerant source
  *     that is quietly serving expired keys looks perfectly healthy from the
  *     outside; `outage` is how you find out before the cached keys run out
  *
  * ==Spans==
  *
  * Validation, the denylist lookup and introspection each open a child span, so
  * a slow request shows exactly which of the three consumed the time.
  * Rejections are *not* span errors — a 401 is a normal outcome — but
  * [[AuthError.ValidationUnavailable]] and a thrown denylist error are.
  *
  * The JWKS instruments are the exception: Nimbus fetches keys on its own
  * threads through synchronous Java callbacks, so those are metrics only,
  * bridged to `F` through a [[cats.effect.std.Dispatcher]]. Recording is
  * fire-and-forget — telemetry must never fail or delay a key fetch.
  */
trait AuthTelemetry[F[_]] {

  def instrumentValidator(
      validator: AccessTokenValidator[F]
  ): AccessTokenValidator[F]

  def instrumentDenylist(denylist: TokenDenylist[F]): TokenDenylist[F]

  def instrumentIntrospection(
      introspection: TokenIntrospection[F]
  ): TokenIntrospection[F]

  /** Times Nimbus's JWKS HTTP fetches. Wraps the retriever rather than the
    * source, so it sees only real network fetches — never a cache hit.
    */
  def instrumentJwksRetriever(retriever: ResourceRetriever): ResourceRetriever

  def jwksCacheListener[C <: SecurityContext]
      : EventListener[CachingJWKSetSource[C], C]

  def jwksRetryListener[C <: SecurityContext]
      : EventListener[RetryingJWKSetSource[C], C]

  def jwksOutageListener[C <: SecurityContext]
      : EventListener[OutageTolerantJWKSetSource[C], C]
}

object AuthTelemetry {

  /** Identity everywhere: ports come back untouched and listeners drop events.
    * The default, so nothing outside a composition root pays for telemetry.
    */
  def noop[F[_]]: AuthTelemetry[F] = new AuthTelemetry[F] {

    def instrumentValidator(
        validator: AccessTokenValidator[F]
    ): AccessTokenValidator[F] =
      validator

    def instrumentDenylist(denylist: TokenDenylist[F]): TokenDenylist[F] =
      denylist

    def instrumentIntrospection(
        introspection: TokenIntrospection[F]
    ): TokenIntrospection[F] = introspection

    def instrumentJwksRetriever(
        retriever: ResourceRetriever
    ): ResourceRetriever = retriever

    def jwksCacheListener[C <: SecurityContext]
        : EventListener[CachingJWKSetSource[C], C] = _ => ()

    def jwksRetryListener[C <: SecurityContext]
        : EventListener[RetryingJWKSetSource[C], C] = _ => ()

    def jwksOutageListener[C <: SecurityContext]
        : EventListener[OutageTolerantJWKSetSource[C], C] = _ => ()
  }

  /** Buckets in seconds. The lower half resolves a local signature check (tens
    * of microseconds to a few ms); the upper half resolves a JWKS fetch or an
    * introspection round trip stuck behind a timeout.
    */
  private val DurationBuckets: BucketBoundaries =
    BucketBoundaries(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
      1.0, 2.5, 5.0)

  def otel[F[_]: Async: Tracer](
      meter: Meter[F]
  ): Resource[F, AuthTelemetry[F]] =
    for {
      // Nimbus calls the JWKS listeners synchronously from its own threads;
      // `await = false` so a shutdown mid-fetch is never held up by telemetry.
      dispatcher <- Dispatcher.parallel[F](await = false)
      validation <- Resource.eval(
        duration(meter, "auth.validation.duration", "Access token validation")
      )
      denylist <- Resource.eval(
        duration(meter, "auth.denylist.duration", "Revocation denylist lookup")
      )
      introspection <- Resource.eval(
        duration(
          meter,
          "auth.introspection.duration",
          "RFC 7662 introspection call"
        )
      )
      jwksFetch <- Resource.eval(
        duration(meter, "auth.jwks.fetch.duration", "JWKS HTTP fetch")
      )
      jwksEvents <- Resource.eval(
        meter
          .counter[Long]("auth.jwks.events")
          .withDescription(
            "JWKS key source lifecycle events, by stable event name"
          )
          .create
      )
    } yield new Otel[F](
      dispatcher,
      validation,
      denylist,
      introspection,
      jwksFetch,
      jwksEvents
    )

  private def duration[F[_]](
      meter: Meter[F],
      name: String,
      description: String
  ): F[Histogram[F, Double]] =
    meter
      .histogram[Double](name)
      .withUnit("s")
      .withDescription(description)
      .withExplicitBucketBoundaries(DurationBuckets)
      .create

  private final class Otel[F[_]: Async: Tracer](
      dispatcher: Dispatcher[F],
      validationDuration: Histogram[F, Double],
      denylistDuration: Histogram[F, Double],
      introspectionDuration: Histogram[F, Double],
      jwksFetchDuration: Histogram[F, Double],
      jwksEvents: Counter[F, Long]
  ) extends AuthTelemetry[F] {

    def instrumentValidator(
        validator: AccessTokenValidator[F]
    ): AccessTokenValidator[F] =
      new AccessTokenValidator[F] {

        def validate(token: String): F[Either[AuthError, AuthContext]] =
          Tracer[F].spanBuilder("auth.validate_token").build.use { span =>
            Clock[F].timed(validator.validate(token)).flatMap {
              case (elapsed, result) =>
                val attribute = Attribute(
                  "auth.outcome",
                  result.fold(outcomeCode, _ => "success")
                )
                validationDuration.record(seconds(elapsed), attribute) *>
                  span.addAttribute(attribute) *>
                  markUnavailable(span, result).as(result)
            }
          }

        // A rejected token is a normal outcome, not a failed span. Keys being
        // unreachable is not: that is the fail-closed 503 path.
        private def markUnavailable(
            span: Span[F],
            result: Either[AuthError, AuthContext]
        ): F[Unit] =
          result match {
            case Left(AuthError.ValidationUnavailable) =>
              span.setStatus(StatusCode.Error)
            case _ => Async[F].unit
          }
      }

    def instrumentDenylist(denylist: TokenDenylist[F]): TokenDenylist[F] =
      new TokenDenylist[F] {

        def isRevoked(tokenId: String): F[Boolean] =
          Tracer[F].spanBuilder("auth.denylist.check").build.use { span =>
            // `attempt` observes a store failure without changing it: the
            // error is re-raised untouched, exactly as the caller saw it
            // before this decorator existed.
            Clock[F].timed(denylist.isRevoked(tokenId).attempt).flatMap {
              case (elapsed, outcome) =>
                val attribute = Attribute(
                  "auth.denylist.outcome",
                  outcome.fold(
                    _ => "error",
                    revoked => if (revoked) "revoked" else "allowed"
                  )
                )
                denylistDuration.record(seconds(elapsed), attribute) *>
                  span.addAttribute(attribute) *>
                  span.setStatus(StatusCode.Error).whenA(outcome.isLeft) *>
                  Async[F].fromEither(outcome)
            }
          }
      }

    def instrumentIntrospection(
        introspection: TokenIntrospection[F]
    ): TokenIntrospection[F] =
      new TokenIntrospection[F] {

        def check(rawToken: String): F[TokenIntrospection.Result] =
          Tracer[F].spanBuilder("auth.introspection.check").build.use { span =>
            Clock[F].timed(introspection.check(rawToken)).flatMap {
              case (elapsed, result) =>
                val attribute = Attribute(
                  "auth.introspection.result",
                  result match {
                    case TokenIntrospection.Result.Active      => "active"
                    case TokenIntrospection.Result.Inactive    => "inactive"
                    case TokenIntrospection.Result.Unavailable => "unavailable"
                  }
                )
                introspectionDuration.record(seconds(elapsed), attribute) *>
                  span.addAttribute(attribute) *>
                  span
                    .setStatus(StatusCode.Error)
                    .whenA(
                      result == TokenIntrospection.Result.Unavailable
                    )
                    .as(result)
            }
          }
      }

    def instrumentJwksRetriever(
        retriever: ResourceRetriever
    ): ResourceRetriever =
      (url: URL) => {
        val startedAt = System.nanoTime()
        try {
          val resource = retriever.retrieveResource(url)
          recordFetch("success", startedAt)
          resource
        } catch {
          case error: Throwable =>
            recordFetch("failure", startedAt)
            throw error
        }
      }

    def jwksCacheListener[C <: SecurityContext]
        : EventListener[CachingJWKSetSource[C], C] =
      event => countJwksEvent(cacheEventName(event))

    def jwksRetryListener[C <: SecurityContext]
        : EventListener[RetryingJWKSetSource[C], C] =
      _ => countJwksEvent("retrial")

    def jwksOutageListener[C <: SecurityContext]
        : EventListener[OutageTolerantJWKSetSource[C], C] =
      _ => countJwksEvent("outage")

    private def recordFetch(outcome: String, startedAtNanos: Long): Unit = {
      val elapsedSeconds = (System.nanoTime() - startedAtNanos) / 1e9
      dispatcher.unsafeRunAndForget(
        jwksFetchDuration
          .record(elapsedSeconds, Attribute("auth.jwks.outcome", outcome))
      )
    }

    private def countJwksEvent(name: String): Unit =
      dispatcher.unsafeRunAndForget(
        jwksEvents.inc(Attribute("auth.jwks.event", name))
      )
  }

  private def cacheEventName(event: Event[?, ?]): String = event match {
    case _: CachingJWKSetSource.RefreshInitiatedEvent[?]  => "refresh_initiated"
    case _: CachingJWKSetSource.RefreshCompletedEvent[?]  => "refresh_completed"
    case _: CachingJWKSetSource.RefreshTimedOutEvent[?]   => "refresh_timed_out"
    case _: CachingJWKSetSource.WaitingForRefreshEvent[?] =>
      "waiting_for_refresh"
    case _: CachingJWKSetSource.UnableToRefreshEvent[?] => "unable_to_refresh"
    case _                                              => "unknown"
  }

  private def seconds(elapsed: FiniteDuration): Double =
    elapsed.toUnit(TimeUnit.SECONDS)
}
