package http

import com.typesafe.config.ConfigFactory
import munit.FunSuite

class RateLimitRegistrySpec extends FunSuite {

  private val config = ConfigFactory.parseString(
    """
    default { permits = 2, window = 1 minute }
    token   { permits = 1, window = 1 minute }
    """
  )

  test("resolves configured policies with their own limits") {
    val registry = RateLimitRegistry.fromConfig(config)

    val token = registry.get("token")
    assertEquals(token.tryAcquire("k"), true)
    assertEquals(token.tryAcquire("k"), false)

    // Distinct policy instances: "default" still has its own budget for the same key.
    assertEquals(registry.get("default").tryAcquire("k"), true)
  }

  test("unknown policy fails fast, naming the configured policies") {
    val registry = RateLimitRegistry.fromConfig(config)
    val error = intercept[IllegalArgumentException](registry.get("no-such-policy"))
    assert(error.getMessage.contains("no-such-policy"))
    assert(error.getMessage.contains("default"))
    assert(error.getMessage.contains("token"))
  }

  test("a config with no policies is rejected at construction") {
    intercept[IllegalArgumentException] {
      RateLimitRegistry.fromConfig(ConfigFactory.empty())
    }
  }
}
