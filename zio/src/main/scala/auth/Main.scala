package auth

import auth.accesstoken.TokenVerification
import sage.backend.SageClient
import zio.*
import zio.http.*

/**
  * The ZIO/zio-http build of the service: same environment variables, same Redis keys, same shared
  * auth core as the http4s service's `app.MultiNodeMain`, for a like-for-like comparison of the two
  * runtimes. Configuration is this module's own `application.conf`, read with zio-config
  * ([[ServiceConfig]]); logging is scribe ([[Logging]]).
  *
  * `-Dauth.zio.avoidContextSwitching=true` runs handlers on Netty's event loop instead of shifting
  * them to the ZIO executor (zio-http's `avoidContextSwitching`).
  */
object Main extends ZIOAppDefault {

  // ZIO's own logs (including a boot failure) go to scribe from the start.
  override val bootstrap: ZLayer[ZIOAppArgs, Any, Any] = Logging.layer

  def run: ZIO[Any, Throwable, Unit] =
    for {
      cfg <- ServiceConfig.load
      _   <- ZIO.succeed(Logging.configure(cfg.logLevel))
      _   <- ZIO.scoped(serve(cfg))
    } yield ()

  private def serve(cfg: ServiceConfig): ZIO[Scope, Throwable, Unit] =
    for {
      redis     <- SageClient.scoped(cfg.redis.toSageConfig)
      tokens     = cfg.auth.toAccessTokenConfig
      keySource <- ZIO.acquireRelease(ZIO.attempt(TokenVerification.keySource(tokens))) {
                     case closeable: java.io.Closeable =>
                       ZIO.attemptBlocking(closeable.close()).orDie
                     case _ => ZIO.unit
                   }
      _       <- ZIO.attemptBlocking(TokenVerification.requireKeys(tokens, keySource))
      denylist = {
        val store = TokenDenylist.redis(redis, cfg.redis.commandTimeout)
        if (tokens.revocationCacheTtl.length > 0)
          TokenDenylist.cached(
            store,
            tokens.revocationCacheTtl,
            tokens.revocationCacheMaxEntries
          )
        else store
      }
      events    = new AuthEvents()
      validator = new AccessTokenValidator(tokens, keySource, denylist, events)
      config    =
        Server.Config.default
          .binding(cfg.http.host, cfg.http.port)
          .idleTimeout(cfg.http.idleTimeout)
          .gracefulShutdownTimeout(cfg.http.shutdownTimeout)
          .avoidContextSwitching(sys.props.get("auth.zio.avoidContextSwitching").contains("true"))
      _ <- ZIO.logInfo(s"ZIO server starting on ${cfg.http.host}:${cfg.http.port}")
      _ <- Server
             .serve(HttpApi.routes(validator, events, cfg.http))
             .provide(Server.live, ZLayer.succeed(config))
    } yield ()

}
