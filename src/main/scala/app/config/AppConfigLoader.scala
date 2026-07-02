package app.config

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import app.config.given
import pureconfig.ConfigSource
import pureconfig.error.ConfigReaderException

object AppConfigLoader {

  def load[F[_]](using F: Sync[F]): F[AppConfig] =
    F.fromEither(
      ConfigSource.default
        .at("app")
        .load[AppConfig]
        .leftMap(ConfigReaderException[AppConfig](_))
    ).flatTap(cfg =>
      F.delay(cfg.auth.toAuthConfig).void
    ) // force AuthConfig.require at startup
}
