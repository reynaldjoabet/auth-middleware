package app.infra.postgres

import cats.effect.{Resource, Sync}
import cats.syntax.all.catsSyntaxApplicativeError
import cats.syntax.flatMap.*

import app.config.DbConfig
import com.zaxxer.hikari.{HikariConfig, HikariDataSource}
import org.flywaydb.core.Flyway
import org.slf4j.LoggerFactory

object Database {

  private val log = LoggerFactory.getLogger(getClass)

  def pool[F[_]](
      cfg: DbConfig
  )(using F: Sync[F]): Resource[F, HikariDataSource] =
    Resource.fromAutoCloseable(
      F.blocking {
        val hc = new HikariConfig()
        hc.setPoolName("auth-pool")
        hc.setJdbcUrl(cfg.jdbcUrl)
        hc.setUsername(cfg.user)
        hc.setPassword(cfg.password.value)
        hc.setMaximumPoolSize(cfg.maxPoolSize)
        hc.setMinimumIdle(cfg.maxPoolSize)
        hc.setConnectionTimeout(cfg.connectTimeout.toMillis)
        hc.setMaxLifetime(cfg.maxLifetime.toMillis)
        hc.setLeakDetectionThreshold(cfg.leakDetectionThreshold.toMillis)
        hc.setKeepaliveTime(120_000L)
        new HikariDataSource(hc)
      }
    )

  /**
    * Applies pending Flyway migrations from `classpath:db/migration`, using the app's own pool so
    * migration and runtime provably talk to the same database.
    *
    * Runs before the server binds, and a failure aborts the boot: a node whose schema is not at the
    * expected version must never start serving. Flyway takes a database-level lock for the
    * duration, so rolling out N replicas at once is safe — the first to acquire it migrates, the
    * rest wait and then find nothing pending.
    *
    * @param baselineOnMigrate
    *   one-shot adoption switch for a database that already carries the schema (someone applied the
    *   SQL by hand). It marks the current state as the baseline instead of failing on "relation
    *   already exists" — which also means it *skips* V1 rather than applying it, so leave it off in
    *   steady state or a genuinely empty database silently comes up empty.
    */
  def migrate[F[_]](
      ds: HikariDataSource,
      baselineOnMigrate: Boolean = false
  )(using F: Sync[F]): F[Unit] =
    F.blocking {
      Flyway
        .configure(getClass.getClassLoader)
        .dataSource(ds)
        .locations("classpath:db/migration")
        // Checksum drift on an already-applied migration means the file was
        // edited after the fact; fail rather than run on an unknown schema.
        .validateOnMigrate(true)
        // `clean` drops every object in the schema. Nothing in this service
        // ever wants that, so make it structurally unavailable.
        .cleanDisabled(true)
        .baselineOnMigrate(baselineOnMigrate)
        // The pool is already up, so the database is reachable; a couple of
        // retries only cover a failover flapping at exactly the wrong moment.
        .connectRetries(3)
        .connectRetriesInterval(2)
        .load()
        .migrate()
    }.flatMap(result =>
      F.delay(
        log.info(
          "Schema migration complete: {} migration(s) applied, schema version {}",
          result.migrationsExecuted,
          Option(result.targetSchemaVersion)
            .orElse(Option(result.initialSchemaVersion))
            .getOrElse("unknown")
        )
      )
    )

  /**
    * Readiness probe: borrow a connection and validate it, never throwing.
    */
  def ping[F[_]](ds: HikariDataSource)(using F: Sync[F]): F[Boolean] =
    F.blocking {
      val c = ds.getConnection
      try c.isValid(2)
      finally c.close()
    }.handleError(_ => false)

}
