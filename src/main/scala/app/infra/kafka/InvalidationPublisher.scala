package app.infra.kafka

import cats.effect.{Async, Resource}
import cats.effect.implicits.parallelForGenSpawn
import cats.syntax.all.*
import fs2.kafka.{Acks, KafkaProducer, ProducerSettings, Serializer}

import auth.revocation.TokenInvalidation

/**
  * The publishing side, for the token service (or an admin tool) to emit invalidations in the wire
  * format [[KafkaInvalidations]] reads.
  *
  * [[publish]] returns once the broker has acknowledged the record on every in-sync replica
  * (`acks=all`, idempotent). Only then is the invalidation certain to reach every node, so
  * acknowledge a revocation to whoever asked for it after this returns, not before.
  */
final class InvalidationPublisher[F[_]: Async] private (
    producer: KafkaProducer[F, String, String],
    topic: String
) {

  def publish(invalidation: TokenInvalidation): F[Unit] =
    producer
      .produceOne_(
        topic,
        InvalidationCodec.keyOf(invalidation),
        InvalidationCodec.encode(invalidation)
      )
      .flatten
      .void

}

object InvalidationPublisher {

  def resource[F[_]: Async](
      bootstrapServers: String,
      topic: String,
      properties: Map[String, String] = Map.empty
  ): Resource[F, InvalidationPublisher[F]] =
    KafkaProducer
      .resource(
        ProducerSettings(Serializer.string[F], Serializer.string[F])
          .withBootstrapServers(bootstrapServers)
          .withProperties(properties)
          .withAcks(Acks.All)
          .withEnableIdempotence(true)
      )
      .map(new InvalidationPublisher[F](_, topic))

}
