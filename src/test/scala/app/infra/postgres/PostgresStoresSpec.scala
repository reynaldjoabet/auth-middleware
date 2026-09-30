package app.infra.postgres

import java.util.concurrent.TimeoutException
import java.util.UUID

import scala.concurrent.duration.*

import cats.effect.{IO, Resource}
import cats.syntax.all.*

import app.config.{DbConfig, PostgresStoreSettings, Secret}
import app.infra.postgres.PostgresStores.*
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*
import munit.CatsEffectSuite
import skunk.codec.all.{bool, text}
import skunk.implicits.*

/**
  * The Postgres stores against a real database, migrated with the service's own Flyway scripts.
  *
  * Runs only when `TEST_POSTGRES_PORT` is set (CI starts a Postgres service for it); otherwise the
  * suite is skipped. `TEST_POSTGRES_HOST`, `_DB`, `_USER` and `_PASSWORD` default to a local
  * trust-auth database `auth` owned by `auth`, the one `bench/loadtest/run.sh` creates.
  */
class PostgresStoresSpec extends CatsEffectSuite {

  private def env(name: String, default: String): String =
    sys.env.get(s"TEST_POSTGRES_$name").filter(_.nonEmpty).getOrElse(default)

  private val port = sys.env.get("TEST_POSTGRES_PORT").flatMap(_.toIntOption)

  override def munitIgnore: Boolean = port.isEmpty

  private val db = DbConfig(
    host = env("HOST", "127.0.0.1"),
    port = port.getOrElse(5432).refineUnsafe[Interval.Closed[1, 65535]],
    name = env("DB", "auth"),
    user = env("USER", "auth"),
    password = new Secret(env("PASSWORD", "unused")),
    maxPoolSize = 2,
    connectTimeout = 5.seconds,
    maxLifetime = 30.minutes,
    leakDetectionThreshold = 10.seconds,
    migrateOnStart = true,
    baselineOnMigrate = false
  )

  private val settings = PostgresStoreSettings(
    sessions = 4,
    commandTimeout = 1.second,
    synchronousCommit = false,
    maxBatch = 64,
    sweepInterval = 100.millis,
    sweepBatch = 2
  )

  private def poolOf(sessions: Int, timeout: FiniteDuration): Resource[IO, SessionPool[IO]] =
    SessionPool.resource[IO](
      PostgresStores.session[IO](db, settings.copy(commandTimeout = timeout)),
      sessions,
      timeout
    )

  /**
    * The stores twice over one pool: as configured, and with no retention margin so expiry can be
    * tested in milliseconds.
    */
  private final case class Fixture(pool: SessionPool[IO], stores: Stores[IO], unpadded: Stores[IO])

  private val fixture = ResourceSuiteLocalFixture(
    "stores",
    for {
      _        <- Database.pool[IO](db).evalTap(Database.migrate[IO](_))
      pool     <- poolOf(settings.sessions, settings.commandTimeout)
      stores   <- Stores.resource[IO](pool, settings)
      unpadded <- Stores.resource[IO](pool, settings, retentionMargin = Duration.Zero)
    } yield Fixture(pool, stores, unpadded)
  )

  override def munitFixtures = List(fixture)

  private def key(): String = UUID.randomUUID().toString

  private val stillStored =
    sql"SELECT EXISTS (SELECT 1 FROM auth.dpop_spent_jtis WHERE jti = $text)".query(bool)

  // --- DPoP proof jtis ------------------------------------------------------

  test("a jti is spent once") {
    val store = fixture().stores.jtis
    val jti   = key()
    for {
      first  <- store.markUsed(jti, 1.minute)
      second <- store.markUsed(jti, 1.minute)
    } yield {
      assert(first)
      assert(!second)
    }
  }

  test("of 32 concurrent spends of one jti, exactly one wins") {
    val store = fixture().stores.jtis
    val jti   = key()
    List
      .fill(32)(store.markUsed(jti, 1.minute))
      .parSequence
      .map(results => assertEquals(results.count(identity), 1))
  }

  test("concurrent spends of many jtis, repeats included, each win exactly once") {
    val store = fixture().stores.jtis
    val jtis  = List.fill(200)(key())
    // Every jti three times, shuffled, so batches mix new keys and repeats.
    scala.util.Random
      .shuffle(jtis ++ jtis ++ jtis)
      .parTraverse(jti => store.markUsed(jti, 1.minute).map(jti -> _))
      .map { results =>
        val wins = results.groupMapReduce(_._1)(r => if (r._2) 1 else 0)(_ + _)
        assertEquals(wins.values.toSet, Set(1))
      }
  }

  test("an expired jti reads as unspent, before any sweep") {
    val store = fixture().unpadded.jtis
    val jti   = key()
    for {
      first <- store.markUsed(jti, 1.milli)
      _     <- IO.sleep(50.millis)
      again <- store.markUsed(jti, 1.minute)
      after <- store.markUsed(jti, 1.minute)
    } yield {
      assert(first)
      assert(again, "an expired entry must not block a new spend")
      assert(!after, "the new spend must hold for its own retention")
    }
  }

  // --- revocation -----------------------------------------------------------

  test("a revoked token stays revoked until its expiry, then reads as not revoked") {
    val denylist       = fixture().stores.denylist
    val (live, lapsed) = (key(), key())
    for {
      before  <- denylist.isRevoked(live)
      _       <- denylist.revoke(live, 1.minute)
      _       <- denylist.revoke(lapsed, 1.milli)
      _       <- IO.sleep(50.millis)
      revoked <- denylist.isRevoked(live)
      expired <- denylist.isRevoked(lapsed)
    } yield {
      assert(!before)
      assert(revoked)
      assert(!expired)
    }
  }

  test("revoking again never shortens a revocation") {
    val denylist = fixture().stores.denylist
    val jti      = key()
    denylist.revoke(jti, 1.minute) *> denylist.revoke(jti, 1.milli) *> IO.sleep(50.millis) *>
      denylist.isRevoked(jti).assert
  }

  test("concurrent checks, batched together, each get their own token's answer") {
    val denylist         = fixture().stores.denylist
    val (revoked, clean) = (List.fill(50)(key()), List.fill(50)(key()))
    for {
      _       <- revoked.traverse_(denylist.revoke(_, 1.minute))
      answers <- scala.util.Random
                   .shuffle(revoked ++ clean ++ revoked)
                   .parTraverse(jti => denylist.isRevoked(jti).map(jti -> _))
    } yield answers.foreach((jti, answer) => assertEquals(answer, revoked.contains(jti), jti))
  }

  // --- single-use nonces ----------------------------------------------------

  test("a minted nonce is consumed once; unknown and expired nonces never") {
    val store   = fixture().stores.nonces(1.minute)
    val shortly = fixture().stores.nonces(1.milli)
    for {
      nonce   <- store.mint
      first   <- store.consume(nonce.value)
      second  <- store.consume(nonce.value)
      unknown <- store.consume(key())
      stale   <- shortly.mint
      _       <- IO.sleep(50.millis)
      expired <- store.consume(stale.value)
    } yield {
      assert(first)
      assert(!second)
      assert(!unknown)
      assert(!expired)
    }
  }

  test("of concurrent consumes of one nonce, exactly one succeeds") {
    val store = fixture().stores.nonces(1.minute)
    for {
      nonce   <- store.mint
      results <- List.fill(32)(store.consume(nonce.value)).parSequence
    } yield assertEquals(results.count(identity), 1)
  }

  // --- sweeper --------------------------------------------------------------

  test("the sweeper deletes expired rows, in batches") {
    val store = fixture().unpadded.jtis
    val jtis  = List.fill(5)(key())
    for {
      _    <- jtis.traverse_(store.markUsed(_, 1.milli))
      _    <- IO.sleep(50.millis)
      _    <- Sweeper[IO](fixture().pool, settings).background.surround(IO.sleep(800.millis))
      left <- jtis.traverse(jti => fixture().pool.use(_.unique(stillStored)(jti)))
    } yield assertEquals(left.count(identity), 0, "batches of 2, so it took several statements")
  }

  // --- failing closed -------------------------------------------------------

  test("with every session busy, a call fails with a timeout instead of waiting") {
    val short = settings.copy(commandTimeout = 200.millis)
    (poolOf(sessions = 1, timeout = 200.millis) >>= (p =>
      Stores.resource[IO](p, short).tupleLeft(p)
    ))
      .use { (busy, stores) =>
        for {
          // Uncancelable, like a Skunk exchange: the pool's deadline cannot
          // take the session back, only stop waiting for it.
          _       <- busy.use(_ => IO.sleep(2.seconds).uncancelable).attempt.start
          _       <- IO.sleep(50.millis)
          started <- IO.monotonic
          result  <- stores.denylist.isRevoked(key()).attempt
          ended   <- IO.monotonic
        } yield {
          assert(result.left.exists(_.isInstanceOf[TimeoutException]), result.toString)
          assert(ended - started < 1.second, s"took ${ended - started}")
        }
      }
  }

  test("statement_timeout ends a stalled statement, so its session serves again") {
    val stall = sql"SELECT true FROM pg_sleep(5)".query(bool)
    val short = settings.copy(commandTimeout = 200.millis)
    (poolOf(sessions = 1, timeout = 200.millis) >>= (p =>
      Stores.resource[IO](p, short).tupleLeft(p)
    ))
      .use { (one, stores) =>
        for {
          stalled <- one.use(_.unique(stall)).attempt
          // Postgres cancels the statement at 200 ms and the session comes
          // back; without statement_timeout it would stay busy for 5 s.
          _     <- IO.sleep(300.millis)
          after <- stores.denylist.isRevoked(key())
        } yield {
          assert(stalled.left.exists(_.isInstanceOf[TimeoutException]), stalled.toString)
          assert(!after)
        }
      }
  }

}
