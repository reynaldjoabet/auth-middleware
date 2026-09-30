package bench

import cats.effect.{ExitCode, IO, IOApp}

import org.http4s.*
import org.http4s.netty.server.NettyServerBuilder
import org.http4s.netty.NettyTransport

/**
  * The Netty-backend counterpart of [[BareEmber]]: answers every request with `200 ok` and nothing
  * else, to compare the two http4s server backends' ceilings on the same machine.
  *
  * Settings (system properties): `bare.port` (18084), `bare.transport` (`native`, the default —
  * kqueue on macOS, epoll/io_uring on Linux — or `nio`), `bare.threads` (event-loop threads; 0 lets
  * Netty choose).
  */
object BareNetty extends IOApp {

  private def prop(name: String): Option[String] = sys.props.get(s"bare.$name")

  def run(args: List[String]): IO[ExitCode] = {
    val base = NettyServerBuilder[IO]
      .bindHttp(prop("port").fold(18084)(_.toInt), "127.0.0.1")
      .withoutBanner
      .withHttpApp(HttpApp[IO](_ => IO.pure(Response[IO](Status.Ok).withEntity("ok"))))
    val transported =
      if (prop("transport").contains("nio")) base.withTransport(NettyTransport.Nio)
      else base.withNativeTransport
    prop("threads")
      .fold(transported)(n => transported.withEventLoopThreads(n.toInt))
      .resource
      .useForever
  }

}
