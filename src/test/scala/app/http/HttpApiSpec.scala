package app.http

import cats.data.{Kleisli, OptionT}
import cats.effect.IO

import auth.AuthContext
import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.implicits.*
import org.http4s.server.AuthMiddleware
import org.typelevel.otel4s.trace.Tracer
import app.http.error.ProblemDetails

/**
  * The composed HTTP stack, as [[app.http.Server]] builds it. These assert *wiring*, not the
  * individual middlewares: each piece has its own spec, and every one of them passed while the
  * stack itself had no error net at all.
  */
class HttpApiSpec extends CatsEffectSuite {

  private given Tracer[IO] = Tracer.noop[IO]

  /**
    * Rejects everything: the protected routes are exercised in [[auth.AccessTokenAuthSpec]], and
    * the probes below are open.
    */
  private val rejectAll: AuthMiddleware[IO, AuthContext] =
    _ => Kleisli(_ => OptionT.none[IO, Response[IO]])

  private def app(isReady: IO[Boolean] = IO.pure(true)): HttpApp[IO] =
    HttpApi.httpApp[IO](isReady, rejectAll)

  private def requestIdOf(response: Response[IO]): Option[String] =
    response.headers.get(RequestId.HeaderName).map(_.head.value)

  test("an unexpected error renders problem+json, never a bare 500") {
    val boom =
      IO.raiseError[Boolean](new RuntimeException("readiness exploded"))
    app(boom).run(Request[IO](Method.GET, uri"/ready")).flatMap { response =>
      response.as[String].map { body =>
        assertEquals(response.status.code, 500)
        assertEquals(
          response.contentType.map(_.mediaType),
          Some(ProblemDetails.MediaTypeProblemJson)
        )
        // The failure text must not reach the client.
        assert(!body.contains("exploded"), body)
      }
    }
  }

  test("the 500 body quotes the same request id as the response header") {
    val boom = IO.raiseError[Boolean](new RuntimeException("boom"))
    app(boom).run(Request[IO](Method.GET, uri"/ready")).flatMap { response =>
      response.as[String].map { body =>
        val assigned = requestIdOf(response)
        assert(assigned.exists(_.nonEmpty), "no request id was assigned")
        // RFC 7807 `instance` carries the id, so the caller can quote the value
        // they already hold from the response header.
        assert(body.contains(s""""instance":"${assigned.get}""""), body)
      }
    }
  }

  test("a client-supplied request id is echoed back") {
    val request = Request[IO](Method.GET, uri"/health")
      .putHeaders(Header.Raw(RequestId.HeaderName, "abc-123"))
    app()
      .run(request)
      .map(response => assertEquals(requestIdOf(response), Some("abc-123")))
  }

  test("a request id that could forge a log record is replaced, not echoed") {
    val injected = "abc\r\n2026-07-28 ERROR forged line"
    val request  = Request[IO](Method.GET, uri"/health")
      .putHeaders(Header.Raw(RequestId.HeaderName, injected))
    app().run(request).map { response =>
      val assigned = requestIdOf(response)
      assert(assigned.isDefined, "a fresh id must be minted")
      assertNotEquals(assigned, Some(injected))
      assert(!assigned.exists(_.contains("\n")), assigned.toString)
    }
  }

  test("an over-long request id is replaced") {
    val request = Request[IO](Method.GET, uri"/health")
      .putHeaders(Header.Raw(RequestId.HeaderName, "x" * 65))
    app()
      .run(request)
      .map(response => assertNotEquals(requestIdOf(response), Some("x" * 65)))
  }

  test("probes stay open and report readiness") {
    for {
      health   <- app().run(Request[IO](Method.GET, uri"/health"))
      ready    <- app().run(Request[IO](Method.GET, uri"/ready"))
      notReady <- app(IO.pure(false)).run(Request[IO](Method.GET, uri"/ready"))
    } yield {
      assertEquals(health.status.code, 200)
      assertEquals(ready.status.code, 200)
      assertEquals(notReady.status.code, 503)
    }
  }

}
