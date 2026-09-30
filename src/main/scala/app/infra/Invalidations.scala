package app.infra

import scala.concurrent.duration.Duration

import cats.effect.{IO, Resource}

import auth.revocation.InvalidationStore
import app.config.AppConfig
import app.infra.kafka.KafkaInvalidations

/**
  * The Kafka-fed revocation copy, when `app.revocation.kafka` is enabled.
  */
object Invalidations {

  def resource(cfg: AppConfig): Resource[IO, Option[InvalidationStore[IO]]] =
    if (cfg.revocation.kafka.enabled)
      KafkaInvalidations.resource[IO](cfg.revocation.kafka).map(Some(_))
    else Resource.pure(None)

  /**
    * With the feed on, revocation checks are map reads: a per-node revocation cache in front of
    * them would only delay revocations, so it is switched off.
    */
  def adjust(cfg: AppConfig): AppConfig =
    if (!cfg.revocation.kafka.enabled) cfg
    else
      cfg.copy(auth = cfg.auth.copy(cache = cfg.auth.cache.copy(revocationTtl = Duration.Zero)))

}
