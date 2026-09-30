package app.infra.kafka

import java.time.Instant

import scala.concurrent.duration.*

import cats.effect.{Async, Ref, Resource}
import cats.effect.syntax.spawn.*
import cats.syntax.all.*
import fs2.kafka.{AutoOffsetReset, ConsumerSettings, Deserializer, KafkaConsumer}
import fs2.Stream

import auth.revocation.InvalidationStore
import app.config.KafkaInvalidationSettings
import org.apache.kafka.common.TopicPartition
import org.slf4j.LoggerFactory

/**
  * Follows the token service's invalidation topic and keeps this node's [[InvalidationStore]]
  * current.
  *
  * ==Every node reads every partition==
  *
  * A consumer group would split the partitions among the nodes, and each node would then see only
  * its share of the invalidations. So there is no group: the consumer assigns itself every
  * partition of the topic and commits nothing.
  *
  * ==Catching up on start==
  *
  * A node that has just started knows nothing, so it replays the topic from `max-token-lifetime`
  * (plus a margin) ago: anything older revokes only tokens that have expired anyway. Until it has
  * caught up, the store fails revocation checks closed and `/ready` reports not ready, so no
  * request is answered from a partial copy.
  *
  * ==Knowing it is current==
  *
  * Every `freshness-check-interval`, the node notes the time and the topic's end offsets. When it
  * has applied everything up to those offsets, it knows every invalidation published before that
  * time is in its copy, and marks the store fresh as of then. If that stops happening for
  * `max-staleness` (broker unreachable, consumer stuck), the store fails checks closed.
  *
  * ==Failures==
  *
  * If the consumer fails it is rebuilt after `retry-backoff` and replays the same window. Applying
  * an invalidation twice changes nothing. A record that isn't a valid invalidation is logged at
  * ERROR and skipped: it can never become valid, and stopping on it would stop every revocation
  * behind it.
  */
object KafkaInvalidations {

  private val log = LoggerFactory.getLogger(getClass)

  /**
    * Pads the replay window, for clock skew between the token service and the broker.
    */
  private val ReplayMargin = 5.minutes

  def resource[F[_]: Async](
      settings: KafkaInvalidationSettings
  ): Resource[F, InvalidationStore[F]] =
    for {
      store <- Resource.eval(
                 InvalidationStore[F](settings.maxTokenLifetime, settings.maxStaleness)
               )
      _ <- follow(store, settings).background
    } yield store

  private def consumerSettings[F[_]: Async](
      settings: KafkaInvalidationSettings
  ): ConsumerSettings[F, Option[String], Option[String]] =
    ConsumerSettings(
      Deserializer.string[F].option,
      Deserializer.string[F].option
    ).withBootstrapServers(settings.bootstrapServers)
      // A mistyped topic name must not quietly create an empty topic that
      // this node would then follow, report ready on, and never see a
      // revocation in. Missing, it keeps the node not ready and retrying.
      .withProperty("allow.auto.create.topics", "false")
      .withProperties(settings.properties.view.mapValues(_.value).toMap)
      .withEnableAutoCommit(false)
      .withAutoOffsetReset(AutoOffsetReset.Earliest)
      .withClientId("auth-middleware-invalidations")

  // Runs until the resource is released, rebuilding the consumer after a failure.
  private def follow[F[_]: Async](
      store: InvalidationStore[F],
      settings: KafkaInvalidationSettings
  ): F[Unit] =
    consume(store, settings).handleErrorWith { error =>
      Async[F].delay(
        log.warn(
          s"Invalidation consumer for ${settings.topic} failed; reconnecting in ${settings.retryBackoff}",
          error
        )
      ) *> Async[F].sleep(settings.retryBackoff)
    }.foreverM

  private def consume[F[_]: Async](
      store: InvalidationStore[F],
      settings: KafkaInvalidationSettings
  ): F[Unit] =
    KafkaConsumer.resource(consumerSettings[F](settings)).use { consumer =>
      for {
        partitions <- consumer
                        .partitionsFor(settings.topic)
                        .map(_.map(p => new TopicPartition(p.topic, p.partition)).toSet)
        _ <- Async[F].raiseWhen(partitions.isEmpty)(
               new IllegalStateException(s"topic ${settings.topic} has no partitions")
             )
        _   <- consumer.assign(settings.topic)
        now <- Async[F].realTimeInstant
        from = now.minusNanos((settings.maxTokenLifetime + ReplayMargin).toNanos)
        // The first offset at or after `from` in each partition; a partition
        // with nothing that recent starts at its end.
        found <- consumer.offsetsForTimes(partitions.map(_ -> from.toEpochMilli).toMap)
        _     <- partitions.toList.traverse_ { partition =>
               found.get(partition).flatten match {
                 case Some(offset) => consumer.seek(partition, offset.offset)
                 case None         => consumer.seekToEnd(List(partition))
               }
             }
        start <- partitions.toList
                   .traverse(p => consumer.position(p).tupleLeft(p))
                   .map(_.toMap)
        applied <- Ref.of[F, Map[TopicPartition, Long]](start)
        _       <- Async[F].delay(
               log.info(
                 s"Following ${settings.topic} (${partitions.size} partitions) from $from"
               )
             )
        _ <- consumer.records
               .evalMap { committable =>
                 val record = committable.record
                 apply(store, record.value, record.topic, record.partition, record.offset) *>
                   applied.update(
                     _.updated(
                       new TopicPartition(record.topic, record.partition),
                       record.offset + 1
                     )
                   )
               }
               .concurrently(freshness(consumer, partitions, applied, store, settings))
               .compile
               .drain
      } yield ()
    }

  private def apply[F[_]: Async](
      store: InvalidationStore[F],
      value: Option[String],
      topic: String,
      partition: Int,
      offset: Long
  ): F[Unit] =
    value match {
      // A tombstone: compaction clearing a key. Nothing to apply.
      case None       => Async[F].unit
      case Some(json) =>
        InvalidationCodec.decode(json) match {
          case Right(invalidation) => store.apply(invalidation)
          case Left(error)         =>
            Async[F].delay(
              log.error(
                s"Skipping $topic-$partition@$offset: not a token invalidation (${error.getMessage})"
              )
            )
        }
    }

  /**
    * Every `freshness-check-interval`: if everything up to the end offsets seen last time has been
    * applied, the store is current as of that time.
    */
  private def freshness[F[_]: Async](
      consumer: KafkaConsumer[F, ?, ?],
      partitions: Set[TopicPartition],
      applied: Ref[F, Map[TopicPartition, Long]],
      store: InvalidationStore[F],
      settings: KafkaInvalidationSettings
  ): Stream[F, Unit] = {
    val snapshot: F[(Instant, Map[TopicPartition, Long])] =
      // The time first: every record acknowledged before it is below these ends.
      (Async[F].realTimeInstant, consumer.endOffsets(partitions)).tupled

    Stream.eval(snapshot).flatMap { first =>
      Stream.unfoldEval(first) { case (asOf, ends) =>
        Async[F].sleep(settings.freshnessCheckInterval) *>
          applied.get.flatMap { done =>
            val caughtUp = ends.forall((p, end) => done.getOrElse(p, 0L) >= end)
            store.markFresh(asOf).whenA(caughtUp)
          } *> snapshot.map(next => Some(((), next)))
      }
    }
  }

}
