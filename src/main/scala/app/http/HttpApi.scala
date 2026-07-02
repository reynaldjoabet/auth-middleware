package app.http

import auth.AuthContext
import auth.given
import cats.effect.Async
import cats.syntax.all.*
import com.zaxxer.hikari.HikariDataSource
import org.http4s.dsl.Http4sDsl
import org.http4s.implicits.*
import org.http4s.server.AuthMiddleware
import org.http4s.{AuthedRoutes, HttpApp, HttpRoutes}
import app.infra.postgres.Database

/** The HTTP surface: open liveness/readiness probes plus the access-token
  * protected API mounted behind [[auth.BearerAuth]].
  *
  *   - `GET /health` — liveness, never touches the DB
  *   - `GET /ready` — readiness, validates a pooled connection
  *   - `GET /me` — example protected route; the [[AuthContext]] is the
  *     authenticated principal injected by the middleware
  */
object HttpApi {

  def httpApp[F[_]: Async](
      ds: HikariDataSource,
      authMiddleware: AuthMiddleware[F, AuthContext]
  ): HttpApp[F] = {
    val dsl = Http4sDsl[F]
    import dsl.*

    val open = HttpRoutes.of[F] {
      case GET -> Root / "health" => Ok("ok")
      case GET -> Root / "ready"  =>
        Database
          .ping[F](ds)
          .flatMap(ready =>
            if (ready) Ok("ready") else ServiceUnavailable("db unavailable")
          )
    }

    val secured = authMiddleware(AuthedRoutes.of[AuthContext, F] {
      case GET -> Root / "me" as ctx => Ok(s"sub=${ctx.subject}")
    })

    (open <+> secured).orNotFound
  }
}
