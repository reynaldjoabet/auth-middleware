package app.infra.kafka

import java.time.Instant
import java.util.UUID

import scala.concurrent.duration.*

import cats.effect.{IO, Resource}
import cats.syntax.all.*
import fs2.kafka.{AdminClientSettings, KafkaAdminClient, KafkaProducer, ProducerSettings}

import auth.revocation.{InvalidationStore, TokenInvalidation}
import app.config.KafkaInvalidationSettings
import io.github.iltotore.iron.*
import munit.CatsEffectSuite
import org.apache.kafka.clients.admin.NewTopic

/**
  * [[KafkaInvalidations]] against a real broker: replay on start, broadcast to every node, and a
  * malformed record skipped rather than wedging the feed.
  *
  * Runs only when `TEST_KAFKA_BOOTSTRAP` is set (CI starts a Kafka service for it); otherwise the
  * suite is skipped. Each test uses a topic of its own with three partitions, so a node that read
  * only some partitions would miss invalidations and fail.
  */
class KafkaInvalidationsSpec extends CatsEffectSuite {

  private val bootstrap = sys.env.get("TEST_KAFKA_BOOTSTRAP").filter(_.nonEmpty)

  override def munitIgnore: Boolean = bootstrap.isEmpty

  override def munitIOTimeout: Duration = 90.seconds

  private def settings(topic: String) = KafkaInvalidationSettings(
    enabled = true,
    bootstrapServers = bootstrap.getOrElse("localhost:9092").refineUnsafe,
    topic = topic.refineUnsafe,
    maxTokenLifetime = 1.hour,
    maxStaleness = 30.seconds,
    freshnessCheckInterval = 200.millis,
    retryBackoff = 500.millis,
    properties = Map.empty
  )

  private def freshTopic: Resource[IO, String] = {
    val topic = s"auth.token-invalidations.test-${UUID.randomUUID()}"
    KafkaAdminClient
      .resource[IO](AdminClientSettings(bootstrap.getOrElse("")))
      .evalMap(admin => admin.createTopic(new NewTopic(topic, 3, 1.toShort)).as(topic))
  }

  private def publisher(topic: String) =
    InvalidationPublisher.resource[IO](bootstrap.getOrElse(""), topic)

  private def awaitReady(store: InvalidationStore[IO]): IO[Unit] =
    store.ready
      .flatMap(ready => if (ready) IO.unit else IO.sleep(100.millis) *> awaitReady(store))
      .timeoutTo(30.seconds, IO.raiseError(new AssertionError("store never caught up")))

  private def eventually(check: IO[Boolean], what: String): IO[Unit] =
    check
      .flatMap(ok => if (ok) IO.unit else IO.sleep(100.millis) *> eventually(check, what))
      .timeoutTo(15.seconds, IO.raiseError(new AssertionError(s"never saw: $what")))

  private val later = Instant.now().plusSeconds(600)

  test("a node that starts later replays what was published before it, then is ready") {
    (freshTopic >>= (topic => publisher(topic).tupleLeft(topic))).use { (topic, publish) =>
      val jtis = List.fill(30)(UUID.randomUUID().toString)
      for {
        _     <- jtis.traverse_(jti => publish.publish(TokenInvalidation.Token(jti, later)))
        _     <- publish.publish(TokenInvalidation.Subject("u-7", Instant.now(), Some("roles-changed")))
        found <-
          KafkaInvalidations.resource[IO](settings(topic)).use { store =>
            awaitReady(store) *>
              (jtis.traverse(store.isRevoked), store.subjects.get.revokedBefore("u-7")).tupled
          }
      } yield {
        assert(found._1.forall(identity), "every jti published before start, on all 3 partitions")
        assert(found._2.isDefined)
      }
    }
  }

  test("every node sees every invalidation: no consumer group splits the partitions") {
    (freshTopic >>= (topic => publisher(topic).tupleLeft(topic))).use { (topic, publish) =>
      val nodes = (
        KafkaInvalidations.resource[IO](settings(topic)),
        KafkaInvalidations.resource[IO](settings(topic))
      ).tupled
      nodes.use { (a, b) =>
        val jtis = List.fill(30)(UUID.randomUUID().toString)
        for {
          _ <- awaitReady(a) *> awaitReady(b)
          _ <- jtis.traverse_(jti => publish.publish(TokenInvalidation.Token(jti, later)))
          _ <- eventually(jtis.traverse(a.isRevoked).map(_.forall(identity)), "all on node a")
          _ <- eventually(jtis.traverse(b.isRevoked).map(_.forall(identity)), "all on node b")
        } yield ()
      }
    }
  }

  test("a missing topic keeps the node not ready, and is not created behind its back") {
    val topic = s"auth.token-invalidations.missing-${UUID.randomUUID()}"
    for {
      ready <- KafkaInvalidations
                 .resource[IO](settings(topic))
                 .use(store => IO.sleep(3.seconds) *> store.ready)
      topics <- KafkaAdminClient
                  .resource[IO](AdminClientSettings(bootstrap.getOrElse("")))
                  .use(_.listTopics.names)
    } yield {
      assert(!ready)
      assert(!topics.contains(topic), "the consumer must not auto-create the topic")
    }
  }

  test("a malformed record is skipped; what follows it is applied") {
    (freshTopic >>= (topic => publisher(topic).tupleLeft(topic))).use { (topic, publish) =>
      val raw = KafkaProducer.resource(
        ProducerSettings[IO, String, String].withBootstrapServers(bootstrap.getOrElse(""))
      )
      val jti = UUID.randomUUID().toString
      KafkaInvalidations.resource[IO](settings(topic)).use { store =>
        for {
          _ <- awaitReady(store)
          // Same key, so the same partition: the good record sits behind the bad one.
          _     <- raw.use(_.produceOne_(topic, s"jti:$jti", "{not json").flatten)
          _     <- publish.publish(TokenInvalidation.Token(jti, later))
          _     <- eventually(store.isRevoked(jti), "the record after the malformed one")
          ready <- store.ready
        } yield assert(ready)
      }
    }
  }

}
