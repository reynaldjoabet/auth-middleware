package app.infra.postgres

import app.config.DbConfig

import cats.effect.{Resource, Sync}
import cats.syntax.functor.*
import com.zaxxer.hikari.{HikariConfig, HikariDataSource}
import cats.syntax.all.catsSyntaxApplicativeError

object Database {

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

  /** Readiness probe: borrow a connection and validate it, never throwing. */
  def ping[F[_]](ds: HikariDataSource)(using F: Sync[F]): F[Boolean] =
    F.blocking {
      val c = ds.getConnection
      try c.isValid(2)
      finally c.close()
    }.handleError(_ => false)
}
