package auth

import org.http4s.Method
import org.http4s.Uri.Path
import org.http4s.Uri.Scheme
import org.typelevel.ci.CIString

// Strict equality (`-language:strictEquality`) for the http4s types this
// service compares. They live here rather than in the shared `core` module,
// which has no http4s dependency.
given CanEqual[CIString, CIString] = CanEqual.derived
given CanEqual[Scheme, Scheme]     = CanEqual.derived
given CanEqual[Method, Method]     = CanEqual.derived
given CanEqual[Path, Path]         = CanEqual.derived
