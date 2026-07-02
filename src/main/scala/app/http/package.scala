package app.http

import cats.effect.IO
import com.github.plokhotnyuk.jsoniter_scala.core.*
import org.http4s.*
import org.http4s.headers.`Content-Type`

import scala.util.control.NonFatal

/** Bridges jsoniter-scala codecs into http4s entity (de)serialisation. */

given [A](using JsonValueCodec[A]): EntityDecoder[IO, A] =
  EntityDecoder.byteArrayDecoder[IO].flatMapR { bytes =>
    try DecodeResult.successT[IO, A](readFromArray[A](bytes))
    catch {
      case NonFatal(e) =>
        DecodeResult.failureT[IO, A](
          MalformedMessageBodyFailure(
            Option(e.getMessage).getOrElse("invalid JSON"),
            Some(e)
          )
        )
    }
  }

given [A](using JsonValueCodec[A]): EntityEncoder[IO, A] =
  EntityEncoder
    .byteArrayEncoder[IO]
    .contramap[A](writeToArray(_))
    .withContentType(`Content-Type`(MediaType.application.json))
