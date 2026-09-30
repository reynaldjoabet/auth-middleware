package auth

import java.util.concurrent.atomic.AtomicReference

import cats.effect.unsafe.implicits.global
import cats.effect.IO

import auth.accesstoken.AccessTokenValidator
import auth.revocation.TokenDenylist
import munit.FunSuite
import org.http4s.{AuthedRoutes, Header, Headers, Method, Request, Uri}
import org.http4s.dsl.io.*
import org.typelevel.ci.CIString

/**
  * The shared [[Conformance]] suite against this service's http4s middleware. The ZIO service runs
  * the same cases against its own; passing both means the two make the same decisions.
  */
class ConformanceSpec extends FunSuite {

  import TestTokens.*

  private val state = new AtomicReference[Conformance.Denylist](Conformance.Denylist.Clear)

  private val denylist = new TokenDenylist[IO] {
    def isRevoked(tokenId: String): IO[Boolean] =
      IO(Conformance.isRevoked(state.get, tokenId)).flatMap(IO.fromEither)
  }

  private val app =
    AccessTokenAuth
      .middleware[IO](
        AccessTokenValidator.withKeySource[IO](config, keySource, AuthEvents.noop[IO], denylist),
        AuthEvents.noop[IO],
        realm = Conformance.Realm
      )(AuthedRoutes.of[AuthContext, IO] { case GET -> Root / "me" as ctx =>
        Ok(Conformance.body(ctx))
      })
      .orNotFound

  private def seen(c: Conformance.Case): Conformance.Seen = {
    val request = Request[IO](Method.GET, Uri.unsafeFromString(c.target))
      .withHeaders(Headers(c.authorization.map(v => Header.Raw(CIString("Authorization"), v))))
    val response = app.run(request).unsafeRunSync()
    Conformance.Seen(
      response.status.code,
      Conformance.Compared
        .flatMap(name => response.headers.get(CIString(name)).map(name -> _.head.value))
        .toMap,
      response.as[String].unsafeRunSync()
    )
  }

  Conformance.cases.foreach { c =>
    test(s"conformance: ${c.name}") {
      state.set(c.denylist)
      try assertEquals(seen(c), Conformance.expected(c))
      finally state.set(Conformance.Denylist.Clear)
    }
  }

}
