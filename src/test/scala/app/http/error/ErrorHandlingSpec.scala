package app.http.error

import cats.effect.{IO, Ref}
import io.circe.syntax.*
import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.implicits.*

import app.domain.error.AppError

class ErrorHandlingSpec extends CatsEffectSuite {

  import ToProblemDetails.given

  test("ToProblemDetails maps each AppError to its status") {
    assertEquals(
      AppError.NotFound("Account", "a1").toProblemDetails.status,
      404
    )
    assertEquals(AppError.Conflict("dup").toProblemDetails.status, 409)
    assertEquals(AppError.Validation("bad").toProblemDetails.status, 422)
    assertEquals(AppError.Forbidden("no").toProblemDetails.status, 403)
  }

  test("ProblemDetails serializes `tpe` as the RFC 7807 `type` member") {
    val json = ProblemDetails("about:blank", "X", 404, Some("d")).asJson
    assertEquals(json.hcursor.get[String]("type").toOption, Some("about:blank"))
    assert(json.hcursor.downField("tpe").focus.isEmpty, json.noSpaces)
  }

  test("ErrorMapper.toResponse renders the mapped status as problem+json") {
    val resp =
      ErrorMapper.toResponse[IO, AppError](AppError.NotFound("Account", "a1"))
    assertEquals(resp.status.code, 404)
    assertEquals(
      resp.contentType.map(_.mediaType),
      Some(ProblemDetails.MediaTypeProblemJson)
    )
  }

  test(
    "ErrorMiddleware: unexpected error -> logged 500 problem+json + trace id"
  ) {
    val boom =
      HttpRoutes.of[IO] { case _ =>
        IO.raiseError(new RuntimeException("boom"))
      }
    Ref[IO].of(Option.empty[Throwable]).flatMap { logged =>
      val mw =
        ErrorMiddleware[IO]((_, t) => logged.set(Some(t)).as("trace-123"))(boom)
      mw.orNotFound.run(Request[IO](Method.GET, uri"/x")).flatMap { resp =>
        for {
          body <- resp.as[String]
          lg <- logged.get
        } yield {
          assertEquals(resp.status.code, 500)
          assertEquals(
            resp.contentType.map(_.mediaType),
            Some(ProblemDetails.MediaTypeProblemJson)
          )
          assert(lg.exists(_.getMessage == "boom"), lg.toString)
          assert(body.contains("trace-123"), body)
        }
      }
    }
  }

  test("ErrorMiddleware: MessageFailure -> 4xx, not 500, and not logged") {
    val bad = HttpRoutes.of[IO] { case _ =>
      IO.raiseError(MalformedMessageBodyFailure("nope"))
    }
    Ref[IO].of(false).flatMap { called =>
      val mw = ErrorMiddleware[IO]((_, _) => called.set(true).as("t"))(bad)
      mw.orNotFound.run(Request[IO](Method.GET, uri"/x")).flatMap { resp =>
        called.get.map { wasCalled =>
          assert(
            resp.status.code >= 400 && resp.status.code < 500,
            resp.status.toString
          )
          assert(!wasCalled, "onError must not run for client decode failures")
        }
      }
    }
  }
}
