package app.infra.kafka

import java.time.Instant

import cats.syntax.all.*

import auth.revocation.TokenInvalidation
import io.circe.{Decoder, DecodingFailure, Encoder, Json}
import io.circe.syntax.*

/**
  * The wire format of the invalidation topic: one JSON object per record, `type` first.
  *
  * {{{
  *   {"type":"token",   "jti":"ABC",  "expires_at":"2026-10-01T10:00:00Z"}
  *   {"type":"subject", "sub":"u-42", "issued_before":"2026-10-01T09:05:00Z", "reason":"roles-changed"}
  * }}}
  *
  * The record key is `jti:<jti>` or `sub:<subject>`: every invalidation of one token or one subject
  * lands on the same partition, in order, and a compacted topic keeps the latest of each.
  */
object InvalidationCodec {

  def keyOf(invalidation: TokenInvalidation): String =
    invalidation match {
      case TokenInvalidation.Token(jti, _)          => s"jti:$jti"
      case TokenInvalidation.Subject(subject, _, _) => s"sub:$subject"
    }

  given Encoder[TokenInvalidation] = Encoder.instance {
    case TokenInvalidation.Token(jti, expiresAt) =>
      Json.obj("type" -> "token".asJson, "jti" -> jti.asJson, "expires_at" -> expiresAt.asJson)
    case TokenInvalidation.Subject(subject, before, reason) =>
      Json
        .obj(
          "type"          -> "subject".asJson,
          "sub"           -> subject.asJson,
          "issued_before" -> before.asJson,
          "reason"        -> reason.asJson
        )
        .dropNullValues
  }

  given Decoder[TokenInvalidation] = Decoder.instance { c =>
    def nonBlank(field: String): Decoder.Result[String] =
      c.downField(field).as[String].flatMap { value =>
        if (value.trim.nonEmpty) Right(value)
        else Left(DecodingFailure(s"$field must not be blank", c.history))
      }
    c.downField("type").as[String].flatMap {
      case "token" =>
        (nonBlank("jti"), c.downField("expires_at").as[Instant]).mapN(TokenInvalidation.Token.apply)
      case "subject" =>
        (
          nonBlank("sub"),
          c.downField("issued_before").as[Instant],
          c.downField("reason").as[Option[String]]
        ).mapN(TokenInvalidation.Subject.apply)
      case other => Left(DecodingFailure(s"unknown invalidation type '$other'", c.history))
    }
  }

  def encode(invalidation: TokenInvalidation): String = invalidation.asJson.noSpaces

  def decode(json: String): Either[io.circe.Error, TokenInvalidation] =
    io.circe.jawn.decode[TokenInvalidation](json)

}
