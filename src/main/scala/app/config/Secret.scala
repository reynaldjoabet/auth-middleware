package app.config

import pureconfig.ConfigReader
import pureconfig.error.CannotConvert

/** A config value that must never appear in logs, error messages or dumps:
  * passwords, client secrets, key material. `toString` is redacted, so a
  * `Secret` inside any case class (or the whole [[AppConfig]]) is safe to log;
  * the real value is read only at the point of use via [[value]].
  *
  * The reader rejects blank values: a secret that is present but empty is
  * always a deployment mistake (e.g. `DB_PASSWORD=""`), and must fail the boot
  * rather than authenticate with an empty credential.
  */
final class Secret(val value: String) {
  override def toString: String = "Secret(<redacted>)"
}

object Secret {
  given ConfigReader[Secret] =
    ConfigReader[String].emap(s =>
      if (s.isBlank)
        Left(CannotConvert("<redacted>", "Secret", "must not be blank"))
      else Right(new Secret(s))
    )
}
