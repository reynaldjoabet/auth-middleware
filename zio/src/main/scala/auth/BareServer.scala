package auth

import zio.*
import zio.http.*

/**
  * zio-http answering every request with `200 ok` — the counterpart of `bench.BareEmber`, the
  * ceiling the ZIO service is measured against. Port from `-Dbare.port` (default 18086);
  * `-Dauth.zio.avoidContextSwitching=true` as for [[Main]].
  */
object BareServer extends ZIOAppDefault {

  def run: ZIO[Any, Throwable, Unit] = {
    val config = Server.Config.default
      .binding("127.0.0.1", sys.props.get("bare.port").fold(18086)(_.toInt))
      .avoidContextSwitching(sys.props.get("auth.zio.avoidContextSwitching").contains("true"))
    Server
      .serve(Routes(Method.GET / trailing -> handler(Response.text("ok"))))
      .provide(Server.live, ZLayer.succeed(config))
  }

}
