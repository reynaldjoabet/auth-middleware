package auth
import org.typelevel.ci.*
import org.http4s.Uri.Scheme
import org.http4s.Method
import org.http4s.Uri.Path

given CanEqual[CIString, CIString] = CanEqual.derived
given CanEqual[Scheme, Scheme] = CanEqual.derived
given CanEqual[Method, Method] = CanEqual.derived
given CanEqual[Path, Path] = CanEqual.derived
