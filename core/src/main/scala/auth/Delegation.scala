package auth

import scala.jdk.CollectionConverters.*

import com.nimbusds.jose.util.JSONObjectUtils

/**
  * The party acting on the subject's behalf, from the `act` claim of a token obtained by token
  * exchange (RFC 8693 §4.1): `sub` is the user, `act` is the service now calling with their
  * authority.
  *
  * Only the current actor (the outermost `act`) may inform an access-control decision. Prior actors
  * (nested `act` claims, the most deeply nested being the first) are a history trail for audit, and
  * RFC 8693 §4.1 forbids using them for access control; [[prior]] is kept for logging only.
  *
  * @param subject
  *   the actor's `sub`, when present
  * @param clientId
  *   the actor's `client_id` (RFC 8693 §4.3), when present. At least one of the two identifies the
  *   actor.
  * @param issuer
  *   the actor's `iss`, when it differs from the token's issuer
  */
final case class Actor(
    subject: Option[String],
    clientId: Option[String],
    issuer: Option[String],
    prior: Option[Actor]
) derives CanEqual {

  /**
    * How the actor is shown in logs and sent to a policy decision point.
    */
  def id: String = subject.orElse(clientId).getOrElse("")

  /**
    * This actor followed by every prior one, most recent first. For audit trails only.
    */
  def chain: List[Actor] = this :: prior.toList.flatMap(_.chain)

}

object Actor {

  /**
    * Nested `act` claims beyond this depth are refused: a legitimate chain of service hops is
    * short, and an unbounded one is only a way to make every request do more work.
    */
  val MaxDepth = 10

  /**
    * The actor in a raw `act` claim value (a JSON object, as Nimbus parses it). `Left` when the
    * value is not an object, identifies nobody, or nests too deeply.
    */
  private[auth] def parse(value: Any, depth: Int = 1): Either[String, Actor] =
    value match {
      case _ if depth > MaxDepth        => Left(s"act nests more than $MaxDepth levels")
      case members: java.util.Map[?, ?] =>
        def string(name: String): Option[String] =
          Option(members.get(name)).collect { case s: String if s.trim.nonEmpty => s }
        val subject  = string("sub")
        val clientId = string("client_id")
        if (subject.isEmpty && clientId.isEmpty)
          Left("act identifies no actor: it needs a sub or a client_id")
        else
          Option(members.get("act")) match {
            case None         => Right(Actor(subject, clientId, string("iss"), None))
            case Some(nested) =>
              parse(nested, depth + 1).map(p => Actor(subject, clientId, string("iss"), Some(p)))
          }
      case _ => Left("act is not a JSON object")
    }

}

/**
  * One entry of the `authorization_details` claim (RFC 9396): what the client was authorized to do,
  * more precisely than a scope can say ("initiate this payment of 123.50 EUR to this account").
  *
  * The common fields (RFC 9396 §2.2) are parsed; everything else in the entry, such as an amount or
  * an account, is API-specific and kept as JSON in [[json]] for the handler to decode.
  *
  * Within one entry the grant is the product of its fields: every listed action, at every listed
  * location, on every listed datatype. Separate entries are separate grants and are not combined.
  */
final case class AuthorizationDetail(
    `type`: String,
    locations: List[String],
    actions: List[String],
    datatypes: List[String],
    identifier: Option[String],
    privileges: List[String],
    json: String
) derives CanEqual

object AuthorizationDetail {

  /**
    * The entries of a raw `authorization_details` claim value (a JSON array of objects). `Left`
    * when it is malformed: not an array, an entry that is not an object, or an entry without a
    * `type` (RFC 9396 §2 requires one).
    */
  private[auth] def parseAll(value: Any): Either[String, List[AuthorizationDetail]] =
    value match {
      case entries: java.util.List[?] =>
        entries.asScala.toList.zipWithIndex.foldRight(
          Right(Nil): Either[String, List[AuthorizationDetail]]
        ) { case ((entry, index), acc) =>
          for {
            rest   <- acc
            detail <- parse(entry).left.map(reason => s"authorization_details[$index] $reason")
          } yield detail :: rest
        }
      case _ => Left("authorization_details is not a JSON array")
    }

  private def parse(entry: Any): Either[String, AuthorizationDetail] =
    entry match {
      case members: java.util.Map[?, ?] =>
        def strings(name: String): Either[String, List[String]] =
          Option(members.get(name)) match {
            case None                          => Right(Nil)
            case Some(list: java.util.List[?]) =>
              val values = list.asScala.toList
              if (values.forall(_.isInstanceOf[String]))
                Right(values.collect { case s: String => s })
              else Left(s"has a non-string value in $name")
            case Some(_) => Left(s"$name is not an array")
          }
        for {
          kind <- Option(members.get("type"))
                    .collect { case s: String if s.trim.nonEmpty => s }
                    .toRight("has no type")
          locations  <- strings("locations")
          actions    <- strings("actions")
          datatypes  <- strings("datatypes")
          privileges <- strings("privileges")
          identifier <- Option(members.get("identifier")) match {
                          case None            => Right(None)
                          case Some(s: String) => Right(Some(s))
                          case Some(_)         => Left("identifier is not a string")
                        }
        } yield AuthorizationDetail(
          kind,
          locations,
          actions,
          datatypes,
          identifier,
          privileges,
          JSONObjectUtils.toJSONString(
            members.asInstanceOf[java.util.Map[String, AnyRef]]
          )
        )
      case _ => Left("is not a JSON object")
    }

}

/**
  * What a route requires of the `authorization_details` claim. One entry of the token must grant
  * all of it, as RFC 9396 §2.2 treats an entry's fields as a product and separate entries as
  * separate grants: a token that may read contacts and, in another entry, write photos may not
  * write contacts.
  *
  * @param `type`
  *   the entry type, compared exactly (RFC 9396 types are often URIs)
  * @param actions
  *   each must be listed in the entry
  * @param locations
  *   each must be listed in the entry; name this resource server's URL here so a grant made for
  *   another resource server does not count
  * @param datatypes
  *   each must be listed in the entry
  * @param identifier
  *   when set, the entry's `identifier` must equal it
  * @param privileges
  *   each must be listed in the entry
  */
final case class AuthorizationDetailRequirement(
    `type`: String,
    actions: Set[String] = Set.empty,
    locations: Set[String] = Set.empty,
    datatypes: Set[String] = Set.empty,
    identifier: Option[String] = None,
    privileges: Set[String] = Set.empty
) {

  require(`type`.trim.nonEmpty, "an authorization detail requirement needs a type")

  def isMetBy(detail: AuthorizationDetail): Boolean =
    detail.`type` == `type` &&
      actions.subsetOf(detail.actions.toSet) &&
      locations.subsetOf(detail.locations.toSet) &&
      datatypes.subsetOf(detail.datatypes.toSet) &&
      privileges.subsetOf(detail.privileges.toSet) &&
      identifier.forall(id => detail.identifier.contains(id))

  /**
    * The first entry of `ctx` that meets this requirement: the one a handler should enforce its
    * API-specific fields (an amount, an account) against.
    */
  def firstMatch(ctx: AuthContext): Option[AuthorizationDetail] =
    ctx.authorizationDetails.find(isMetBy)

}
