package auth
import auth.dpop.DpopNonceValidator

import java.nio.charset.StandardCharsets
import java.util.Base64

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.SecretKey

import cats.effect.IO
import cats.effect.kernel.Resource
import org.http4s.Status

/** The stateless (Duende-pattern) nonce adapter: an AES-GCM-encrypted server
  * timestamp, validated by decrypt + freshness check. Exercises the multi-node
  * property (any holder of the key validates any node's nonce), rejection of
  * foreign/tampered/expired values, and the middleware handshake.
  */
class StatelessDpopNonceValidatorSpec extends DpopBaseSuite {
  import DpopNonceValidator.Status as NonceStatus
  import TestTokens.*

  private def newStore: IO[DpopNonceValidator[IO]] =
    DpopNonceValidator
      .randomKey[IO]
      .flatMap(DpopNonceValidator.stateless[IO](_))

  test("issue → validate round-trips") {
    for {
      store <- newStore
      nonce <- store.issue
      status <- store.validate(nonce.value: String)
    } yield assertEquals(status, NonceStatus.Valid)
  }

  test(
    "multi-node: a nonce minted by one store validates on another sharing the key"
  ) {
    for {
      key <- DpopNonceValidator.randomKey[IO]
      nodeA <- DpopNonceValidator.stateless[IO](key)
      nodeB <- DpopNonceValidator.stateless[IO](key)
      nonce <- nodeA.issue
      status <- nodeB.validate(nonce.value: String)
    } yield assertEquals(status, NonceStatus.Valid)
  }

  test("a nonce from a different key is unacceptable") {
    for {
      ours <- newStore
      theirs <- newStore
      foreign <- theirs.issue
      status <- ours.validate(foreign.value: String)
    } yield assertEquals(status, NonceStatus.Unacceptable)
  }

  test(
    "key rotation: a nonce minted under the retired key stays valid while it is in previousKeys"
  ) {
    for {
      oldKey <- DpopNonceValidator.randomKey[IO]
      newKey <- DpopNonceValidator.randomKey[IO]
      before <- DpopNonceValidator.stateless[IO](oldKey)
      nonce <- before.issue
      rotated <- DpopNonceValidator
        .stateless[IO](newKey, previousKeys = List(oldKey))
      dropped <- DpopNonceValidator.stateless[IO](newKey)
      graced <- rotated.validate(nonce.value: String)
      rejected <- dropped.validate(nonce.value: String)
    } yield {
      assertEquals(graced, NonceStatus.Valid)
      assertEquals(rejected, NonceStatus.Unacceptable)
    }
  }

  test("a tampered nonce fails the AEAD tag check") {
    for {
      store <- newStore
      nonce <- store.issue
      raw = nonce.value: String
      flipped = raw.dropRight(1) + (if (raw.last == 'A') 'B' else 'A')
      status <- store.validate(flipped)
    } yield assertEquals(status, NonceStatus.Unacceptable)
  }

  test("garbage and empty values are unacceptable") {
    for {
      store <- newStore
      a <- store.validate("not-a-nonce")
      b <- store.validate("")
      c <- store.validate("x" * 1024)
    } yield {
      assertEquals(a, NonceStatus.Unacceptable)
      assertEquals(b, NonceStatus.Unacceptable)
      assertEquals(c, NonceStatus.Unacceptable)
    }
  }

  test("a nonce older than its lifetime is unacceptable") {
    for {
      key <- DpopNonceValidator.randomKey[IO]
      store <- DpopNonceValidator.stateless[IO](key)
      now <- IO.realTime.map(_.toSeconds)
      stale <- IO(encryptTimestamp(key, now - 3600))
      status <- store.validate(stale)
    } yield assertEquals(status, NonceStatus.Unacceptable)
  }

  test("a nonce from the future beyond the forward skew is unacceptable") {
    for {
      key <- DpopNonceValidator.randomKey[IO]
      store <- DpopNonceValidator.stateless[IO](key)
      now <- IO.realTime.map(_.toSeconds)
      future <- IO(encryptTimestamp(key, now + 3600))
      status <- store.validate(future)
    } yield assertEquals(status, NonceStatus.Unacceptable)
  }

  test(
    "trade-off vs inMemory: a stateless nonce is reusable within its lifetime (freshness proof, not single-use)"
  ) {
    for {
      store <- newStore
      nonce <- store.issue
      first <- store.validate(nonce.value: String)
      second <- store.validate(nonce.value: String)
    } yield {
      assertEquals(first, NonceStatus.Valid)
      assertEquals(second, NonceStatus.Valid)
    }
  }

  // ── through the middleware ────────────────────────────────────────────────

  private def statelessApp(
      shared: Option[SecretKey] = None
  ): Resource[IO, org.http4s.HttpApp[IO]] =
    Resource
      .eval(shared.fold(DpopNonceValidator.randomKey[IO])(IO.pure))
      .flatMap(key => Resource.eval(DpopNonceValidator.stateless[IO](key)))
      .flatMap(store => app(nonces = Some(store)))

  test("middleware: proof without a nonce is challenged, retry succeeds") {
    val token = sign(dpopBoundClaims())
    statelessApp().use { a =>
      for {
        first <- a.run(
          dpopRequest(token, dpopProof("GET", accountsUri.renderString, token))
        )
        _ = assertEquals(first.status, Status.Unauthorized)
        _ = assert(
          challengeOf(first).contains("""error="use_dpop_nonce""""),
          challengeOf(first)
        )
        nonce = nonceOf(first)
        _ = assert(nonce.nonEmpty, "no DPoP-Nonce header issued")
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

  test(
    "middleware, multi-node: a nonce issued by one node is accepted by another (no shared store)"
  ) {
    val token = sign(dpopBoundClaims())
    val nodes = for {
      key <- Resource.eval(DpopNonceValidator.randomKey[IO])
      issuerNode <- Resource.eval(DpopNonceValidator.stateless[IO](key))
      validatorNode <- statelessApp(shared = Some(key))
    } yield (issuerNode, validatorNode)

    nodes.use { case (issuer, a) =>
      issuer.issue.flatMap { nonce =>
        a.run(
          dpopRequest(
            token,
            dpopProof(
              "GET",
              accountsUri.renderString,
              token,
              nonce = Some(nonce.value: String)
            )
          )
        ).map(resp => assertEquals(resp.status, Status.Ok))
      }
    }
  }

  /** Encrypt an arbitrary epoch-second exactly as the store does, to craft
    * expired / future nonces without clock control.
    */
  private def encryptTimestamp(key: SecretKey, epochSeconds: Long): String = {
    val iv = new Array[Byte](12)
    new java.security.SecureRandom().nextBytes(iv)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv))
    val ciphertext = cipher.doFinal(
      epochSeconds.toString.getBytes(StandardCharsets.US_ASCII)
    )
    val out = new Array[Byte](iv.length + ciphertext.length)
    System.arraycopy(iv, 0, out, 0, iv.length)
    System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length)
    Base64.getUrlEncoder.withoutPadding.encodeToString(out)
  }
}
