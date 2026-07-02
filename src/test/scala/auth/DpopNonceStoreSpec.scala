package auth

import org.http4s.Status

/** RFC 9449 §8-9 server-provided DPoP nonces — the FAPI 2.0 fix for DPoP Proof
  * Replay. Exercises the challenge/retry handshake, single-use consumption,
  * rejection of unknown nonces, and §8.2 rotation (a fresh `DPoP-Nonce` on
  * every response to a DPoP request).
  */
class DpopNonceStoreSpec extends DpopBaseSuite {
  import TestTokens.*

  test(
    "a proof with no nonce is challenged with use_dpop_nonce + a DPoP-Nonce"
  ) {
    val token = sign(dpopBoundClaims())
    appWithNonces.use { a =>
      a.run(
        dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
      ).map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        assert(
          challengeOf(resp).contains("""error="use_dpop_nonce""""),
          challengeOf(resp)
        )
        assert(nonceOf(resp).nonEmpty, "no DPoP-Nonce header issued")
      }
    }
  }

  test("retrying with the issued nonce succeeds") {
    val token = sign(dpopBoundClaims())
    appWithNonces.use { a =>
      for {
        first <- a.run(
          dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
        )
        _ = assertEquals(first.status, Status.Unauthorized)
        nonce = nonceOf(first)
        second <- a.run(
          dpopRequest(
            token,
            dpopProof(
              "GET",
              accountsUri.renderString,
              token,
              nonce = Some(nonce)
            )
          )
        )
      } yield assertEquals(second.status, Status.Ok)
    }
  }

  test("a nonce is single-use — replay is re-challenged") {
    val token = sign(dpopBoundClaims())
    appWithNonces.use { a =>
      for {
        first <- a.run(
          dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
        )
        nonce = nonceOf(first)
        // Distinct jti each time, so only the consumed nonce differs.
        ok <- a.run(
          dpopRequest(
            token,
            dpopProof(
              "GET",
              accountsUri.renderString,
              token,
              nonce = Some(nonce)
            )
          )
        )
        _ = assertEquals(ok.status, Status.Ok)
        again <- a.run(
          dpopRequest(
            token,
            dpopProof(
              "GET",
              accountsUri.renderString,
              token,
              nonce = Some(nonce)
            )
          )
        )
        _ = assertEquals(again.status, Status.Unauthorized)
      } yield assert(
        challengeOf(again).contains("""error="use_dpop_nonce""""),
        challengeOf(again)
      )
    }
  }

  test("an unknown nonce is re-challenged, not accepted") {
    val token = sign(dpopBoundClaims())
    appWithNonces.use { a =>
      a.run(
        dpopRequest(
          token,
          dpopProof(
            "GET",
            accountsUri.renderString,
            token,
            nonce = Some("anunknownnoncevalue")
          )
        )
      ).map { resp =>
        assertEquals(resp.status, Status.Unauthorized)
        assert(
          challengeOf(resp).contains("""error="use_dpop_nonce""""),
          challengeOf(resp)
        )
      }
    }
  }

  test(
    "rotation (RFC 9449 §8.2): a successful response carries a fresh DPoP-Nonce, keeping steady state at one round trip"
  ) {
    val token = sign(dpopBoundClaims())
    appWithNonces.use { a =>
      for {
        first <- a.run(
          dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
        )
        n1 = nonceOf(first)
        ok1 <- a.run(
          dpopRequest(
            token,
            dpopProof("GET", accountsUri.renderString, token, nonce = Some(n1))
          )
        )
        _ = assertEquals(ok1.status, Status.Ok)
        n2 = nonceOf(ok1)
        _ = assert(n2.nonEmpty, "success response carried no DPoP-Nonce")
        _ = assertNotEquals(n2, n1, "rotation must mint a fresh nonce")
        // Steady state: the rotated nonce works directly — no 401 round trip.
        ok2 <- a.run(
          dpopRequest(
            token,
            dpopProof("GET", accountsUri.renderString, token, nonce = Some(n2))
          )
        )
      } yield assertEquals(ok2.status, Status.Ok)
    }
  }

  test(
    "recovery: a proof rejected after consuming its nonce still receives a fresh DPoP-Nonce, so one retry suffices"
  ) {
    val token = sign(dpopBoundClaims())
    appWithNonces.use { a =>
      for {
        first <- a.run(
          dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
        )
        n1 = nonceOf(first)
        // Valid nonce but wrong htu: the nonce is consumed, then Nimbus rejects.
        bad <- a.run(
          dpopRequest(
            token,
            dpopProof(
              "GET",
              "https://evil.example/accounts",
              token,
              nonce = Some(n1)
            )
          )
        )
        _ = assertEquals(bad.status, Status.Unauthorized)
        _ = assert(
          challengeOf(bad).contains("""error="invalid_dpop_proof""""),
          challengeOf(bad)
        )
        n2 = nonceOf(bad)
        _ = assert(
          n2.nonEmpty,
          "failure response must carry a fresh DPoP-Nonce for recovery"
        )
        recovered <- a.run(
          dpopRequest(
            token,
            dpopProof("GET", accountsUri.renderString, token, nonce = Some(n2))
          )
        )
      } yield assertEquals(recovered.status, Status.Ok)
    }
  }

  test("no DPoP-Nonce is minted for non-DPoP (Bearer) traffic") {
    val token = sign(claims())
    appWithNonces.use { a =>
      a.run(bearerRequest(token)).map { resp =>
        assertEquals(resp.status, Status.Ok)
        assertEquals(
          nonceOf(resp),
          "",
          "Bearer response must not carry DPoP-Nonce"
        )
      }
    }
  }
}
