package auth

import scala.concurrent.duration.*

import munit.FunSuite
import zio.{Runtime, Unsafe, ZIO}

class ServiceConfigSpec extends FunSuite {

  private def run[A](effect: ZIO[Any, Any, A]): Either[Any, A] =
    Unsafe.unsafe(implicit u => Runtime.default.unsafe.run(effect.either).getOrThrowFiberFailure())

  private def hocon(redis: String = "", auth: String = ""): String =
    s"""app {
       |  http {
       |    host = "0.0.0.0", port = 8080, idle-timeout = 60 seconds
       |    shutdown-timeout = 20 seconds, max-in-flight = 1024, request-timeout = 10 seconds
       |  }
       |  auth {
       |    issuer = "https://issuer.example", audience = "api"
       |    jwks-uri = "https://issuer.example/jwks"
       |    cache { verified-tokens = 100000, verified-token-ttl = 5 minutes, revocation-ttl = 1 second }
       |    $auth
       |  }
       |  redis {
       |    mode = standalone, nodes = [ { host = "localhost", port = 6379 } ]
       |    username = "default", database = 0, tls = false, client-name = "test"
       |    connect-timeout = 10 seconds, ping-interval = 60 seconds, ping-timeout = 30 seconds
       |    command-timeout = 250 milliseconds
       |    $redis
       |  }
       |}""".stripMargin

  test("reads the HOCON the http4s service uses, durations included") {
    val cfg = run(ServiceConfig.fromHocon(hocon())).fold(e => fail(s"$e"), identity)
    assertEquals(cfg.logLevel, scribe.Level.Info)
    assertEquals(cfg.http.requestTimeout, zio.Duration.fromSeconds(10))
    assertEquals(cfg.redis.commandTimeout, 250.millis)
    assertEquals(cfg.auth.toAccessTokenConfig.revocationCacheTtl, 1.second)
    assertEquals(cfg.redis.password, None)
  }

  test("a password never shows in the config's string form") {
    val cfg = run(ServiceConfig.fromHocon(hocon(redis = "password = hunter2")))
      .fold(e => fail(s"$e"), identity)
    assert(!cfg.toString.contains("hunter2"), cfg.toString)
    assertEquals(cfg.redis.password.map(_.stringValue), Some("hunter2"))
  }

  test("rejects a blank password, an http issuer and two standalone nodes") {
    List(
      hocon(redis = "password = \"  \""),
      hocon(auth = "issuer = \"http://issuer.example\""),
      hocon(redis = "nodes = [ { host = a, port = 1 }, { host = b, port = 2 } ]")
    ).foreach(bad => assert(run(ServiceConfig.fromHocon(bad)).isLeft, bad))
  }

}
