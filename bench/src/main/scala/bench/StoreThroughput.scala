package bench

import java.lang.management.ManagementFactory
import java.util.UUID

import scala.concurrent.duration.*

import cats.effect.{IO, IOApp, Resource}
import cats.syntax.all.*

import app.config.*
import app.infra.postgres.{Database, PostgresStores}
import app.infra.redis.{RedisDpopJtiStore, RedisDpopNonceStore, RedisTokenDenylist}
import app.infra.SharedStores
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*
import sage.backend.SageClient
import skunk.implicits.*

/**
  * The shared-state stores on their own, without HTTP or token verification in the way: how many
  * store calls a second each backend answers, how fast, and how much CPU each call costs in this
  * JVM and in the database server.
  *
  * {{{
  *   bench/runMain bench.StoreThroughput <postgres-port> <redis-port> [seconds] [rounds] [fibers]
  * }}}
  *
  * Expects an empty trust-auth database `auth` owned by `auth` and a Redis, both on 127.0.0.1
  * (`bench/loadtest/store-bench.sh` starts both). Every configuration runs once per round, in the
  * same order, so a noisy stretch on the machine hits them all rather than one; the report takes
  * each configuration's median round.
  *
  * Operations, each from `fibers` concurrent callers:
  *   - `check`: is this token revoked? 10% of the `jti`s asked about are revoked
  *   - `spend`: spend a fresh DPoP proof `jti`
  *   - `nonce`: mint a single-use nonce, then consume it (two store calls)
  */
object StoreThroughput extends IOApp {

  private final case class Result(
      ops: Long,
      seconds: Double,
      p50: Double,
      p99: Double,
      errors: Long,
      clientCpu: Double,
      serverCpu: Double
  ) {

    def perSecond: Double = ops / seconds

    def clientMicrosPerOp: Double = clientCpu * 1e6 / ops.max(1)
    def serverMicrosPerOp: Double = serverCpu * 1e6 / ops.max(1)

  }

  def run(args: List[String]): IO[cats.effect.ExitCode] = {
    val pgPort    = args(0).toInt
    val redisPort = args(1).toInt
    val seconds   = args.lift(2).fold(5)(_.toInt)
    val rounds    = args.lift(3).fold(3)(_.toInt)
    val fibers    = args.lift(4).fold(48)(_.toInt)

    val db = DbConfig(
      host = "127.0.0.1",
      port = pgPort.refineUnsafe[Interval.Closed[1, 65535]],
      name = "auth",
      user = "auth",
      password = new Secret("unused"),
      maxPoolSize = 2,
      connectTimeout = 5.seconds,
      maxLifetime = 30.minutes,
      leakDetectionThreshold = 10.seconds,
      migrateOnStart = true,
      baselineOnMigrate = false
    )
    val pgSettings = PostgresStoreSettings(
      sessions = 16,
      commandTimeout = 1.second,
      synchronousCommit = false,
      maxBatch = 256,
      sweepInterval = 30.seconds,
      sweepBatch = 1000
    )
    val redisSettings = RedisSettings(
      mode = RedisMode.Standalone,
      nodes = List(
        RedisEndpoint("127.0.0.1".refineUnsafe, redisPort.refineUnsafe)
      ).refineUnsafe[MinLength[1]],
      username = "default",
      password = None,
      database = 0,
      tls = false,
      clientName = "store-bench",
      connectTimeout = 5.seconds,
      pingInterval = 60.seconds,
      pingTimeout = 30.seconds,
      commandTimeout = 1.second
    )

    val redis: Resource[IO, SharedStores[IO]] =
      SageClient.resource(redisSettings.toSageConfig).map { client =>
        SharedStores[IO](
          RedisTokenDenylist[IO](client, 1.second),
          RedisDpopJtiStore[IO](client, 1.second),
          ttl => new RedisDpopNonceStore[IO](client, 1.second, ttl)
        )
      }

    def postgres(maxBatch: Int): Resource[IO, SharedStores[IO]] =
      PostgresStores.resource[IO](db, pgSettings.copy(maxBatch = maxBatch.refineUnsafe))

    // Admin session: toggles UNLOGGED and empties the tables between runs.
    val admin = PostgresStores.session[IO](db, pgSettings.copy(commandTimeout = 30.seconds))

    def setLogged(logged: Boolean): IO[Unit] = {
      val mode = if (logged) "LOGGED" else "UNLOGGED"
      admin.use { s =>
        List("auth.dpop_spent_jtis", "auth.dpop_nonces").traverse_ { table =>
          s.execute(sql"TRUNCATE #$table".command) *>
            s.execute(sql"ALTER TABLE #$table SET #$mode".command)
        }
      }
    }

    // (name, stores, setup before each run)
    val configs: List[(String, Resource[IO, SharedStores[IO]], IO[Unit])] = List(
      ("redis", redis, IO.unit),
      ("postgres, 1 statement per call", postgres(1), setLogged(true)),
      ("postgres, batched", postgres(256), setLogged(true)),
      ("postgres, batched, UNLOGGED DPoP tables", postgres(256), setLogged(false))
    )

    val revokedJtis = Vector.fill(1000)(UUID.randomUUID().toString)

    def operations(stores: SharedStores[IO]): List[(String, IO[Unit])] = {
      val nonces = stores.nonces(5.minutes)
      List(
        "check" -> IO {
          val random = java.util.concurrent.ThreadLocalRandom.current()
          if (random.nextInt(10) == 0) revokedJtis(random.nextInt(revokedJtis.size))
          else UUID.randomUUID().toString
        }.flatMap(stores.denylist.isRevoked(_).void),
        "spend" -> stores.jtis.markUsed(UUID.randomUUID().toString, 60.seconds).void,
        "nonce" -> nonces.mint.flatMap(n => nonces.consume(n.value)).void
      )
    }

    for {
      // Schema first (Flyway, as the service does), then the revoked set in both stores.
      _       <- Database.pool[IO](db).use(Database.migrate[IO](_))
      _       <- postgres(256).use(s => revokedJtis.traverse_(revoke(s, _)))
      _       <- redis.use(s => revokedJtis.traverse_(revoke(s, _)))
      _       <- IO.println(s"$fibers callers, ${seconds}s per run, $rounds rounds (plus a warm-up)")
      results <- (0 to rounds).toList.flatTraverse { round =>
                   configs.flatTraverse { (name, stores, setup) =>
                     setup *> stores.use { s =>
                       operations(s).traverse { (op, call) =>
                         measure(call, fibers, seconds.seconds).map(r => (round, name, op, r))
                       }
                     }
                   }
                 }
      _ <- report(results.filter(_._1 > 0), configs.map(_._1))
    } yield cats.effect.ExitCode.Success
  }

  private def revoke(stores: SharedStores[IO], jti: String): IO[Unit] =
    stores.denylist match {
      case d: RedisTokenDenylist[IO @unchecked]                   => d.revoke(jti, 1.hour)
      case d: PostgresStores.PostgresTokenDenylist[IO @unchecked] => d.revoke(jti, 1.hour)
      case _                                                      => IO.unit
    }

  /**
    * `fibers` callers each looping `call` for `duration`; latency per call, CPU for the whole run.
    */
  private def measure(call: IO[Unit], fibers: Int, duration: FiniteDuration): IO[Result] =
    for {
      server0  <- serverCpuSeconds
      client0  <- IO(processCpuSeconds)
      start    <- IO.monotonic
      deadline  = start + duration
      perFiber <- List.fill(fibers)(()).parTraverse { _ =>
                    def loop(acc: List[Long], errors: Long): IO[(List[Long], Long)] =
                      IO.monotonic.flatMap { t0 =>
                        if (t0 >= deadline) IO.pure((acc, errors))
                        else
                          call.attempt.flatMap { r =>
                            IO.monotonic.flatMap { t1 =>
                              val took = (t1 - t0).toNanos
                              if (r.isRight) loop(took :: acc, errors) else loop(acc, errors + 1)
                            }
                          }
                      }
                    loop(Nil, 0L)
                  }
      end     <- IO.monotonic
      client1 <- IO(processCpuSeconds)
      server1 <- serverCpuSeconds
    } yield {
      val latencies      = perFiber.flatMap(_._1).toArray.sorted
      def pct(p: Double) =
        if (latencies.isEmpty) 0.0 else latencies(((latencies.length - 1) * p).toInt) / 1e6
      Result(
        ops = latencies.length.toLong,
        seconds = (end - start).toNanos / 1e9,
        p50 = pct(0.50),
        p99 = pct(0.99),
        errors = perFiber.map(_._2).sum,
        clientCpu = client1 - client0,
        serverCpu = server1 - server0
      )
    }

  private def processCpuSeconds: Double =
    ManagementFactory.getOperatingSystemMXBean match {
      case os: com.sun.management.OperatingSystemMXBean => os.getProcessCpuTime / 1e9
      case _                                            => 0.0
    }

  /**
    * CPU time of every `postgres` and `redis-server` process, from `ps`. Both backends' servers are
    * summed; only the one under test is busy during a run.
    */
  private def serverCpuSeconds: IO[Double] =
    IO.blocking {
      val lines = new ProcessBuilder("ps", "-Ao", "time=,comm=").start()
      val out   = new String(lines.getInputStream.readAllBytes())
      lines.waitFor()
      out.linesIterator
        .map(_.trim)
        .filter(l => l.contains("postgres") || l.contains("redis-server"))
        .map(l => parseCpuTime(l.takeWhile(!_.isWhitespace)))
        .sum
    }

  // [[dd-]hh:]mm:ss.cc
  private def parseCpuTime(s: String): Double = {
    val (days, rest) = s.split('-') match {
      case Array(d, r) => (d.toDouble, r)
      case _           => (0.0, s)
    }
    days * 86400 + rest.split(':').foldLeft(0.0)((acc, part) => acc * 60 + part.toDouble)
  }

  private def report(
      results: List[(Int, String, String, Result)],
      order: List[String]
  ): IO[Unit] = IO.println {
    val rows =
      for {
        op   <- List("check", "spend", "nonce")
        name <- order
      } yield {
        val runs   = results.collect { case (_, `name`, `op`, r) => r }.sortBy(_.perSecond)
        val median = runs(runs.size / 2)
        f"$op%-6s $name%-42s ${median.perSecond}%10.0f ${median.p50}%8.2f ${median.p99}%8.2f " +
          f"${median.clientMicrosPerOp}%8.1f ${median.serverMicrosPerOp}%8.1f ${runs.map(_.errors).sum}%7d"
      }
    (f"${"op"}%-6s ${"backend"}%-42s ${"calls/s"}%10s ${"p50 ms"}%8s ${"p99 ms"}%8s " +
      f"${"JVM µs"}%8s ${"DB µs"}%8s ${"errors"}%7s" :: rows).mkString("\n")
  }

}
