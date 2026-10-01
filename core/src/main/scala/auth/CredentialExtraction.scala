package auth

/**
  * Which access-token credential a request presents, independent of any HTTP library. Both services
  * (http4s and ZIO) call this, so they accept and reject exactly the same headers.
  *
  * The `Authorization` grammar is RFC 9110 §11.6.2 (`credentials = auth-scheme [ 1*SP ( token68 /
  * #auth-param ) ]`) as http4s-core implements it, ported rule for rule — including cats-parse's
  * commit semantics, where an alternative is only tried if the previous one failed without
  * consuming input. The http4s service's `AuthorizationFastPathSpec` checks this parser against
  * http4s's own on hand-picked and randomly generated headers.
  */
object CredentialExtraction {

  enum Scheme derives CanEqual {

    case Bearer
    case Dpop

  }

  /**
    * The presented credential.
    *
    * @param tokenInQuery
    *   whether the query string carries an `access_token` parameter. OAuth 2.1 / RFC 6750 §2.3:
    *   query-string tokens leak via logs, referrers and history, so they are rejected even when an
    *   `Authorization` header is also present.
    * @param authorization
    *   every `Authorization` header value on the request
    */
  def extract(
      tokenInQuery: Boolean,
      authorization: List[String],
      dpopEnabled: Boolean
  ): Either[AuthError, (Scheme, String)] =
    if (tokenInQuery) Left(AuthError.InvalidRequest.TokenInQuery)
    else
      authorization match {
        case _ :: _ :: _ => Left(AuthError.InvalidRequest.MultipleCredentials)
        case Nil         => Left(AuthError.MissingToken)
        case raw :: Nil  =>
          tokenCredentialsOf(raw) match {
            case Some(Some((scheme, token))) if scheme.equalsIgnoreCase("Bearer") =>
              Right((Scheme.Bearer, token))
            case Some(Some((scheme, token))) if dpopEnabled && scheme.equalsIgnoreCase("DPoP") =>
              Right((Scheme.Dpop, token))
            case Some(_) => Left(AuthError.InvalidToken.WrongScheme)
            case None    => Left(AuthError.MissingToken)
          }
      }

  /**
    * The credential in one raw `Authorization` value as `(scheme, token68)`; compare the scheme
    * case-insensitively.
    *
    *   - `None`: not a valid credentials value
    *   - `Some(None)`: a valid credentials value in auth-param form (`scheme k=v, …`)
    *   - `Some(Some((scheme, token)))`: a token68 credential
    */
  def tokenCredentialsOf(raw: String): Option[Option[(String, String)]] =
    fastTokenCredentials(raw) match {
      case found @ Some(_) => Some(found)
      case None            => new Parse(raw).credentials()
    }

  /**
    * `auth-scheme SP token68` — the common case, recognised with one scan. `None` when `raw` is not
    * exactly that shape; [[tokenCredentialsOf]] then runs the full grammar.
    *
    * Checks the two parts in place and copies them out only when both are valid: a JWT is about 850
    * characters, so a rejected header costs no allocation.
    */
  def fastTokenCredentials(raw: String): Option[(String, String)] = {
    val space = raw.indexOf(' ')
    if (space <= 0 || !isToken(raw, space) || !isToken68(raw, space + 1)) None
    else Some((raw.substring(0, space), raw.substring(space + 1)))
  }

  // Character classes as 128-entry tables: one array load per character, where a
  // chain of range comparisons costs several branches each. This scan runs over
  // every character of every access token, so it showed up in profiles (about 4%
  // of CPU at 30k requests/s) before the tables.
  private def table(chars: String): Array[Boolean] = {
    val t = new Array[Boolean](128)
    chars.foreach(c => t(c.toInt) = true)
    t
  }

  private val Alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

  // tchar (RFC 9110 §5.6.2)
  private val Tchar = table(Alphanumeric + "!#$%&'*+-.^_`|~")

  // token68 characters, before the trailing "="s (RFC 9110 §11.2)
  private val T68 = table(Alphanumeric + "-._~+/")

  private def isTchar(c: Char): Boolean = c < 128 && Tchar(c.toInt)
  private def isT68(c: Char): Boolean   = c < 128 && T68(c.toInt)

  // `raw[0, end)` is a non-empty token
  private def isToken(raw: String, end: Int): Boolean = {
    var i = 0
    while (i < end && isTchar(raw.charAt(i))) i += 1
    i == end
  }

  // `raw[from, length)` is token68: 1*(…) *"="
  private def isToken68(raw: String, from: Int): Boolean = {
    val length = raw.length
    var i      = from
    while (i < length && isT68(raw.charAt(i))) i += 1
    if (i == from) false
    else {
      while (i < length && raw.charAt(i) == '=') i += 1
      i == length
    }
  }

  /**
    * The full grammar over one value. Each rule returns the end position on success, or a
    * [[Failed]] recording whether input was consumed first — which, as in cats-parse, decides
    * whether an alternative may still be tried.
    */
  private final class Parse(s: String) {

    private final case class Failed(consumed: Boolean)

    private type Result = Either[Failed, Int]

    private def at(i: Int): Int = if (i < s.length) s.charAt(i).toInt else -1

    // token = 1*tchar
    private def token(i: Int): Result = {
      var j = i
      while (j < s.length && isTchar(s.charAt(j))) j += 1
      if (j == i) Left(Failed(consumed = false)) else Right(j)
    }

    // OWS / BWS = *( SP / HTAB ) — never fails
    private def ows(i: Int): Int = {
      var j = i
      while (j < s.length && (s.charAt(j) == ' ' || s.charAt(j) == '\t')) j += 1
      j
    }

    private def isObsText(c: Int): Boolean = c >= 0x80 && c <= 0xff

    private def isQdText(c: Int): Boolean =
      c == '\t' || c == ' ' || c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) ||
        isObsText(c)

    private def isQuotedPairChar(c: Int): Boolean =
      c == '\t' || c == ' ' || (c >= 0x21 && c <= 0x7e) || isObsText(c)

    // quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
    private def quotedString(i: Int): Result =
      if (at(i) != '"') Left(Failed(consumed = false))
      else {
        var j    = i + 1
        var ok   = true
        var done = false
        while (!done) {
          val c = at(j)
          if (isQdText(c)) j += 1
          else if (c == '\\')
            if (isQuotedPairChar(at(j + 1))) j += 2
            else { ok = false; done = true }
          else done = true
        }
        if (ok && at(j) == '"') Right(j + 1) else Left(Failed(consumed = true))
      }

    // auth-param = token BWS "=" BWS ( token / quoted-string ), under `.backtrack`:
    // any failure is reported as not having consumed input.
    private def authParam(i: Int): Result =
      token(i) match {
        case Left(_)          => Left(Failed(consumed = false))
        case Right(afterName) =>
          val eq = ows(afterName)
          if (at(eq) != '=') Left(Failed(consumed = false))
          else {
            val value = ows(eq + 1)
            token(value).orElse(quotedString(value)).left.map(_ => Failed(consumed = false))
          }
      }

    // #auth-param as headerRep1: *( "," OWS ) element *( OWS "," [ OWS element ] )
    private def authParams(i: Int): Result = {
      var j = i
      while (at(j) == ',') j = ows(j + 1)
      val preludeConsumed = j > i
      authParam(j) match {
        case Left(_)    => Left(Failed(consumed = preludeConsumed))
        case Right(end) =>
          var pos  = end
          var tail = Option.empty[Failed]
          var more = true
          while (more) {
            val comma = ows(pos)
            if (at(comma) != ',') {
              // item fails; it consumed input only if OWS matched something
              if (comma > pos) tail = Some(Failed(consumed = true))
              more = false
            } else {
              val next = ows(comma + 1)
              authParam(next) match {
                case Right(after) => pos = after
                case Left(_)      =>
                  // `( OWS element )?`: fine if OWS matched nothing, else a consumed failure
                  if (next > comma + 1) { tail = Some(Failed(consumed = true)); more = false }
                  else pos = comma + 1
              }
            }
          }
          tail.toLeft(pos)
      }
    }

    // token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    private def token68(i: Int): Result = {
      var j = i
      while (j < s.length && isT68(s.charAt(j))) j += 1
      if (j == i) Left(Failed(consumed = false))
      else {
        while (at(j) == '=') j += 1
        Right(j)
      }
    }

    // credentials = auth-scheme SP ( #auth-param / token68 ), matching the whole value
    def credentials(): Option[Option[(String, String)]] =
      token(0) match {
        case Left(_)       => None
        case Right(scheme) =>
          if (at(scheme) != ' ') None
          else {
            val start = scheme + 1
            authParams(start) match {
              case Right(end)                    => Option.when(end == s.length)(None)
              case Left(Failed(consumed = true)) => None
              case Left(_)                       =>
                token68(start) match {
                  case Right(end) if end == s.length =>
                    Some(Some((s.substring(0, scheme), s.substring(start, end))))
                  case _ => None
                }
            }
          }
      }

  }

}
