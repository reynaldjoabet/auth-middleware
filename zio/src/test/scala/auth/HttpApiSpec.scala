package auth

import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}

import com.nimbusds.jose.jwk.{JWK, JWKSelector}
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import munit.FunSuite
import zio.{Promise, Runtime, Unsafe, ZIO}
import zio.http.*

/**
  * The layers around the ZIO middleware, and its verified-token cache.
  */
class HttpApiSpec extends FunSuite {

  import TestTokens.*

  private def run[A](effect: ZIO[Any, Throwable, A]): A =
    Unsafe.unsafe(implicit u => Runtime.default.unsafe.run(effect).getOrThrowFiberFailure())

  private def call(h: HttpApi.H, request: Request): ZIO[Any, Throwable, Response] =
    ZIO.scoped(h.runZIO(request).merge)

  private val ok: HttpApi.H = Handler.succeed(Response.text("ok"))

  test("request id: a safe inbound id is echoed, an unsafe one is replaced") {
    val h        = HttpApi.requestId(ok)
    val safe     = run(call(h, Request.get(URL.root).addHeader("X-Request-ID", "abc-123")))
    val injected = run(call(h, Request.get(URL.root).addHeader("X-Request-ID", "a\nb")))
    assertEquals(safe.headers.rawHeaders("X-Request-ID").toList, List("abc-123"))
    val minted = injected.headers.rawHeaders("X-Request-ID").toList
    assertEquals(minted.size, 1)
    assert(minted.head.matches("[0-9a-f-]{36}"), minted.head)
  }

  test("load shedding: with the only permit held, the next request is shed and probes are not") {
    val inFlight = new AtomicInteger(0)
    val program  =
      for {
        entered <- Promise.make[Nothing, Unit]
        release <- Promise.make[Nothing, Unit]
        stalled  = Handler.fromZIO(entered.succeed(()) *> release.await.as(Response.text("ok")))
        h        = HttpApi.loadShedding(inFlight, max = 1)(stalled)
        held    <- call(h, Request.get(URL.decode("/me").toOption.get)).fork
        _       <- entered.await // the only permit is now taken
        control <- call(h, Request.get(URL.decode("/me").toOption.get))
        probe   <- call(
                   HttpApi.loadShedding(inFlight, max = 1)(ok),
                   Request.get(URL.decode("/health").toOption.get)
                 )
        _      <- release.succeed(())
        served <- held.join
      } yield (control, probe, served)
    val (control, probe, served) = run(program)
    assertEquals(control.status, Status.ServiceUnavailable)
    assertEquals(control.headers.rawHeaders("Retry-After").toList, List("1"))
    assertEquals(probe.status, Status.Ok)
    assertEquals(served.status, Status.Ok)
    assertEquals(inFlight.get, 0) // every permit returned
  }

  test("a reused token is verified once, then served from the cache") {
    val lookups  = new AtomicInteger(0)
    val counting = new JWKSource[SecurityContext] {
      def get(selector: JWKSelector, context: SecurityContext): java.util.List[JWK] = {
        val _ = lookups.incrementAndGet()
        keySource.get(selector, context)
      }
    }
    val validator =
      new AccessTokenValidator(config, counting, TokenDenylist.none, new AuthEvents())
    val token   = sign(claims())
    val results = run(validator.validate(token).zip(validator.validate(token)))
    assert(results._1.isRight && results._2.isRight, results.toString)
    assertEquals(lookups.get, 1)
  }

  test("an unreachable revocation store fails closed, and is asked again next time") {
    val calls                = new AtomicInteger(0)
    val failing              = new AtomicReference[Option[Throwable]](Some(new RuntimeException("blip")))
    val store: TokenDenylist = _ =>
      ZIO.suspend {
        val _ = calls.incrementAndGet()
        failing.getAndSet(None).fold(ZIO.succeed(false))(ZIO.fail(_))
      }
    val validator =
      new AccessTokenValidator(
        config,
        keySource,
        TokenDenylist.cached(store, scala.concurrent.duration.DurationInt(1).minute, 100L),
        new AuthEvents()
      )
    val token  = sign(claims(jti = Some("jti-blip")))
    val first  = run(validator.validate(token))
    val second = run(validator.validate(token))
    assertEquals(first, Left(AuthError.ValidationUnavailable))
    assert(second.isRight, second.toString)
    assertEquals(calls.get, 2) // the failure was not cached
  }

}
