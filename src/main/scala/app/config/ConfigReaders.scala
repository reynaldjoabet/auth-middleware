package app.config

import com.comcast.ip4s.{Host, Port}
import pureconfig.ConfigReader
import pureconfig.error.CannotConvert

given ConfigReader[Host] =
  ConfigReader[String].emap(s =>
    Host
      .fromString(s)
      .toRight(CannotConvert(s, "Host", "not a valid hostname or IP"))
  )

given ConfigReader[Port] =
  ConfigReader[Int].emap(i =>
    Port
      .fromInt(i)
      .toRight(CannotConvert(i.toString, "Port", "must be in 1..65535"))
  )
