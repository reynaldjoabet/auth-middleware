package bench

import java.util.concurrent.atomic.LongAdder
import java.util.concurrent.ConcurrentHashMap

import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*

import cats.effect.{ExitCode, IO, IOApp}
import cats.effect.unsafe.{PollingSystem, SleepSystem}
import fs2.io.net.SocketOption

import com.comcast.ip4s.*
import org.http4s.*
import org.http4s.ember.server.EmberServerBuilder

/**
  * An Ember server that answers every request with `200 ok` and does nothing else — the ceiling a
  * load test of the real service is measured against, and a harness for trying Ember and runtime
  * settings without the auth stack in the way.
  *
  * {{{
  *   java [-Dbare.<setting>=…] -cp <bench classpath> bench.BareEmber
  * }}}
  *
  * Settings (system properties): `bare.port` (18081), `bare.polling` (`selector`, the cats-effect
  * default, or `sleep`, which makes fs2 fall back to NIO2 asynchronous channels),
  * `bare.maxConnections` (1024), `bare.idleTimeout` / `bare.headerTimeout` (seconds, or `inf`),
  * `bare.receiveBuffer` (bytes), `bare.noDelay` (true/false).
  *
  * Every connection-level exception Ember reports is counted by type and printed every 5 seconds,
  * so a load generator's socket errors can be traced to what the server saw.
  */
object BareEmber extends IOApp {

  private def prop(name: String): Option[String] = sys.props.get(s"bare.$name")

  private def duration(name: String): Option[Duration] =
    prop(name).map(v => if (v == "inf") Duration.Inf else v.toInt.seconds)

  protected override def pollingSystem: PollingSystem =
    if (prop("polling").contains("sleep")) SleepSystem else super.pollingSystem

  def run(args: List[String]): IO[ExitCode] = {
    val errors      = new ConcurrentHashMap[String, LongAdder]()
    val requests    = new LongAdder()
    val connections = ConcurrentHashMap.newKeySet[Int]()
    val report      = IO {
      val snapshot = errors.asScala.map { case (k, v) => s"$k=${v.sum}" }.toList.sorted
      System.err.println(
        s"requests=${requests.sum} distinct-client-ports=${connections.size} " +
          s"connection errors: ${snapshot.mkString(", ")}"
      )
    }

    val configured = List[EmberServerBuilder[IO] => EmberServerBuilder[IO]](
      b => duration("idleTimeout").fold(b)(b.withIdleTimeout),
      b => duration("headerTimeout").fold(b)(b.withRequestHeaderReceiveTimeout),
      b => prop("receiveBuffer").fold(b)(v => b.withReceiveBufferSize(v.toInt)),
      b =>
        prop("noDelay").fold(b)(v =>
          b.withAdditionalSocketOptions(List(SocketOption.noDelay(v.toBoolean)))
        )
    ).foldLeft(
      EmberServerBuilder
        .default[IO]
        .withHost(ipv4"127.0.0.1")
        .withPort(prop("port").flatMap(Port.fromString).getOrElse(port"18081"))
        .withMaxConnections(prop("maxConnections").fold(1024)(_.toInt))
        .withHttpApp(HttpApp[IO] { request =>
          IO {
            requests.increment()
            request.remotePort.foreach(p => connections.add(p.value))
            Response[IO](Status.Ok).withEntity("ok")
          }
        })
        .withConnectionErrorHandler { case t =>
          IO {
            val key = t.getClass.getName + Option(t.getMessage).fold("")(m => ": " + m.take(60))
            errors.computeIfAbsent(key, _ => new LongAdder()).increment()
          }
        }
    )((builder, setting) => setting(builder))

    configured.build.use(_ => (IO.sleep(5.seconds) *> report).foreverM)
  }

}
