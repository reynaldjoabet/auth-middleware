package app.config

import munit.FunSuite
import pureconfig.ConfigSource

/** Boot-time configuration invariants: a bad deployment value must fail the
  * boot (loader forces every conversion), never the first request. Exercises
  * the full `app.*` tree including the DPoP nonce and introspection settings
  * shared with the Play stack.
  */
class AppConfigSpec extends FunSuite {

  /** 32 zero bytes, base64 — valid AES-256 key material for tests. */
  private val testKeyB64 =
    java.util.Base64.getEncoder.encodeToString(new Array[Byte](32))

  private def load(authBlock: String): AppConfig =
    ConfigSource
      .string(s"""
        app {
          http {
            host = "0.0.0.0"
            port = 8080
            idle-timeout = 60 seconds
            shutdown-timeout = 30 seconds
            max-connections = 1024
          }
          db {
            host = localhost
            port = 5432
            name = auth
            user = auth
            password = pw
            max-pool-size = 10
            connect-timeout = 5 seconds
            max-lifetime = 30 minutes
            leak-detection-threshold = 10 seconds
          }
          auth {
            issuer = "https://as.test.example"
            audience = "https://api.test.example"
            jwks-uri = "https://as.test.example/jwks"
            $authBlock
          }
          redis {
            mode = standalone
            nodes = [ { host = "localhost", port = 6379 } ]
            username = "default"
            database = 0
            tls = false
            client-name = "auth-middleware"
            connect-timeout = 10 seconds
            ping-interval = 60 seconds
            ping-timeout = 30 seconds
          }
        }
      """)
      .at("app")
      .loadOrThrow[AppConfig]

  private val dpopOn =
    s"""dpop { enabled = true, nonce { enabled = true, key = "$testKeyB64", previous-keys = [], lifetime = 5 minutes } }"""

  private val introspectionOff =
    """introspection { enabled = false, cache-ttl = 10 seconds, request-timeout = 2 seconds }"""

  test("full config loads; nonce key decodes; disabled introspection is None") {
    val cfg = load(s"$dpopOn\n$introspectionOff")
    val _ = cfg.auth.toAccessTokenConfig // AccessTokenConfig.require holds
    assert(cfg.auth.dpop.enabled)
    assert(cfg.auth.dpop.nonce.decodedKey.isDefined)
    assertEquals(cfg.auth.dpop.nonce.decodedPreviousKeys, Nil)
    assertEquals(cfg.auth.introspection.toIntrospectionConfig, None)
  }

  test(
    "absent nonce key is allowed (ephemeral fallback is a wiring decision)"
  ) {
    val cfg = load(
      s"""dpop { enabled = true, nonce { enabled = true, previous-keys = [], lifetime = 5 minutes } }
         $introspectionOff"""
    )
    assertEquals(cfg.auth.dpop.nonce.decodedKey, None)
  }

  test("a nonce key of invalid length fails the boot-time conversion") {
    val shortKey =
      java.util.Base64.getEncoder.encodeToString(new Array[Byte](7))
    val cfg = load(
      s"""dpop { enabled = true, nonce { enabled = true, key = "$shortKey", previous-keys = [], lifetime = 5 minutes } }
         $introspectionOff"""
    )
    intercept[IllegalArgumentException](cfg.auth.dpop.nonce.decodedKey)
  }

  test(
    "enabled introspection without an endpoint fails the boot-time conversion"
  ) {
    val cfg = load(
      s"""$dpopOn
         introspection { enabled = true, cache-ttl = 10 seconds, request-timeout = 2 seconds }"""
    )
    intercept[IllegalArgumentException](
      cfg.auth.introspection.toIntrospectionConfig
    )
  }

  test("complete introspection settings convert with https enforced") {
    val cfg = load(
      s"""$dpopOn
         introspection {
           enabled = true
           endpoint = "https://as.test.example/introspect"
           client-id = "rs-client"
           client-secret = "s3cret"
           cache-ttl = 10 seconds
           request-timeout = 2 seconds
         }"""
    )
    val ic = cfg.auth.introspection.toIntrospectionConfig
    assert(ic.isDefined)
    assertEquals(ic.get.clientId, "rs-client")
  }
}
