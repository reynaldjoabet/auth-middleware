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
      // Force every config-derived invariant at startup: AccessTokenConfig.require,
      // introspection completeness, and nonce key material decoding — a bad
      // value must fail the boot, not the first request that exercises it.
      F.delay {
        val _ = cfg.auth.toAccessTokenConfig
        val _ = cfg.auth.introspection.toIntrospectionConfig
        val _ = cfg.auth.dpop.nonce.decodedKey
        val _ = cfg.auth.dpop.nonce.decodedPreviousKeys
      }.void
    )
}
