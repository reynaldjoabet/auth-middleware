package app.config

import scala.concurrent.duration.*

import io.github.iltotore.iron.autoRefine
import munit.FunSuite

class RedisSettingsSpec extends FunSuite {

  private def settings(nodes: List[RedisEndpoint]): RedisSettings =
    RedisSettings(
      mode = RedisMode.Standalone,
      nodes = nodes,
      username = "user",
      password = None,
      database = 0,
      tls = true,
      clientName = "auth",
      connectTimeout = 1.second,
      pingInterval = 1.second,
      pingTimeout = 1.second
    )

  test(
    "rejects an empty node list at construction (every entrypoint needs Redis)"
  ) {
    intercept[IllegalArgumentException](settings(Nil))
  }

  test("a non-empty node list constructs and maps to a Sage config") {
    val s = settings(List(RedisEndpoint("localhost", 6379)))
    assertEquals(s.nodes.size, 1)
    // toSageConfig must not throw for a valid single-node standalone setup.
    val _ = s.toSageConfig
  }
}
