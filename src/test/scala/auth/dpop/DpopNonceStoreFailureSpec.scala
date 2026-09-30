package auth
package dpop

import cats.effect.IO

import org.http4s.Status

/**
  * A stateful nonce store (e.g. Redis) that cannot be reached must fail DPoP requests closed with
  * `503` — never `500`, never accept — and a failure to mint the *rotation* nonce must not change
  * the outcome of a request that already succeeded.
  */
class DpopNonceStoreFailureSpec extends DpopBaseSuite {

  import TestTokens.*

  private val storeDown = new java.util.concurrent.TimeoutException("redis stalled")

  /**
    * Neither minting nor consuming works.
    */
  private val down: DpopNonceStore[IO] = new DpopNonceStore[IO] {
    def mint: IO[DpopNonce]                     = IO.raiseError(storeDown)
    def consume(presented: String): IO[Boolean] = IO.raiseError(storeDown)
  }

  /**
    * Accepts any presented nonce, but cannot mint a new one.
    */
  private val cannotMint: DpopNonceStore[IO] = new DpopNonceStore[IO] {
    def mint: IO[DpopNonce]                     = IO.raiseError(storeDown)
    def consume(presented: String): IO[Boolean] = IO.pure(true)
  }

  private def withStore(store: DpopNonceStore[IO]) =
    app(dpopNonceValidator = Some(DpopNonceValidator.fromStore(store)))

  test("an unreachable store fails a proof that carries a nonce with 503") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof("GET", accountsUri.renderString, token, nonce = Some("n-1"))
    withStore(down).use(
      _.run(dpopRequest(token, proof)).map(r => assertEquals(r.status, Status.ServiceUnavailable))
    )
  }

  test("an unreachable store fails the use_dpop_nonce challenge with 503") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof("GET", accountsUri.renderString, token)
    withStore(down).use(
      _.run(dpopRequest(token, proof)).map(r => assertEquals(r.status, Status.ServiceUnavailable))
    )
  }

  test("failing to mint the rotation nonce leaves a successful response successful") {
    val token = sign(dpopBoundClaims())
    val proof = dpopProof("GET", accountsUri.renderString, token, nonce = Some("n-1"))
    withStore(cannotMint).use(_.run(dpopRequest(token, proof)).map { response =>
      assertEquals(response.status, Status.Ok)
      assertEquals(nonceOf(response), "")
    })
  }

}
