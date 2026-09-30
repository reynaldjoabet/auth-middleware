package auth

import java.util.concurrent.atomic.AtomicReference

import munit.FunSuite
import zio.{Runtime, Unsafe, ZIO}
import zio.http.{handler, withContext, Header, Headers, Method, Request, Response, Routes, URL}

/**
  * The shared [[Conformance]] suite against this service's zio-http middleware. The http4s service
  * runs the same cases against its own; passing both means the two make the same decisions.
  */
class ConformanceSpec extends FunSuite {

  import TestTokens.*

  private val state = new AtomicReference[Conformance.Denylist](Conformance.Denylist.Clear)

  private val denylist: TokenDenylist = tokenId =>
    ZIO.suspend(ZIO.fromEither(Conformance.isRevoked(state.get, tokenId)))

  private val events = new AuthEvents()

  private val app: Routes[Any, Response] =
    Routes(
      Method.GET / "me" -> handler((_: Request) =>
        withContext((ctx: AuthContext) => Response.text(Conformance.body(ctx)))
      )
    ) @@ AccessTokenAuth.aspect(
      new AccessTokenValidator(config, keySource, denylist, events),
      events,
      realm = Conformance.Realm
    )

  private def seen(c: Conformance.Case): Conformance.Seen = {
    val request = Request
      .get(URL.decode(c.target).toOption.get)
      .addHeaders(Headers(c.authorization.map(v => Header.Custom("Authorization", v))*))
    val observed = ZIO.scoped(app.runZIO(request)).flatMap { response =>
      response.body.asString.map { body =>
        Conformance.Seen(
          response.status.code,
          Conformance.Compared
            .flatMap(name => response.headers.rawHeaders(name).headOption.map(name -> _))
            .toMap,
          body
        )
      }
    }
    Unsafe.unsafe(implicit u => Runtime.default.unsafe.run(observed).getOrThrowFiberFailure())
  }

  Conformance.cases.foreach { c =>
    test(s"conformance: ${c.name}") {
      state.set(c.denylist)
      try assertEquals(seen(c), Conformance.expected(c))
      finally state.set(Conformance.Denylist.Clear)
    }
  }

}
