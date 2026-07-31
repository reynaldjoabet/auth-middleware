package app.http

import cats.data.Kleisli
import cats.effect.MonadCancelThrow
import cats.syntax.all.*

import org.http4s.{Headers, HttpApp, Request, Response}
import org.typelevel.ci.CIString
import org.typelevel.otel4s.context.propagation.TextMapGetter
import org.typelevel.otel4s.trace.{SpanKind, StatusCode, Tracer}
import org.typelevel.otel4s.Attribute

/**
  * OpenTelemetry server spans for the HTTP surface.
  *
  * Continues the caller's trace when the request carries W3C `traceparent` headers and starts a
  * fresh one when it does not, so a 503 from this service lands in the same trace as the gateway
  * hop that produced it. Every span the auth path opens ([[auth.AuthTelemetry]]) is a child of the
  * span opened here.
  *
  * ==Span naming==
  *
  * The name is the request method alone. HTTP semantic conventions want `{method} {http.route}`,
  * but http4s routes are pattern matches rather than registered templates, so the only route-ish
  * string available is the concrete path — and `GET /users/7f3a…` as a span *name* would blow up
  * cardinality in every tracing backend. The conventions call for exactly this fallback when no
  * low-cardinality route is known; the concrete path still travels as the `url.path` attribute.
  *
  * Probe endpoints are excluded: they are hit every few seconds per replica, carry no trace context
  * and would otherwise dominate the trace volume.
  */
object ServerTracing {

  val DefaultExcludedPaths: Set[String] = Set("/health", "/ready")

  def httpApp[F[_]: MonadCancelThrow: Tracer](
      app: HttpApp[F],
      excludedPaths: Set[String] = DefaultExcludedPaths
  ): HttpApp[F] =
    Kleisli { request =>
      if (excludedPaths.contains(request.uri.path.renderString)) app(request)
      else traced(app, request)
    }

  private def traced[F[_]: MonadCancelThrow: Tracer](
      app: HttpApp[F],
      request: Request[F]
  ): F[Response[F]] =
    Tracer[F].joinOrRoot(request.headers) {
      Tracer[F]
        .spanBuilder(request.method.name)
        .withSpanKind(SpanKind.Server)
        .addAttributes(requestAttributes(request))
        .build
        .use { span =>
          // otel4s already marks the span failed on a raised error or
          // cancellation; a *returned* 5xx is invisible to it, so record that
          // here — for this service it is the fail-closed 503 that matters.
          app(request).flatTap { response =>
            span.addAttribute(
              Attribute(
                "http.response.status_code",
                response.status.code.toLong
              )
            ) *> span
              .setStatus(StatusCode.Error)
              .whenA(response.status.code >= 500)
          }
        }
    }

  private def requestAttributes[F[_]](
      request: Request[F]
  ): List[Attribute[?]] = {
    val base = List(
      Attribute("http.request.method", request.method.name),
      Attribute("url.path", request.uri.path.renderString)
    )
    val scheme = request.uri.scheme.map(s => Attribute("url.scheme", s.value))
    val host   = request.uri.host.map(h => Attribute("server.address", h.value))
    // The correlation id a caller can quote in a support ticket, indexed
    // alongside the span so one lookup finds the other.
    val requestId =
      RequestId.find(request).map(id => Attribute("http.request.id", id))
    base ++ scheme.toList ++ host.toList ++ requestId.toList
  }

  /**
    * W3C context extraction from http4s headers. otel4s ships getters for map-like carriers only;
    * `Headers` is a list of raw name/value pairs, so it needs this one-liner.
    */
  private given TextMapGetter[Headers] with {

    def get(carrier: Headers, key: String): Option[String] =
      carrier.get(CIString(key)).map(_.head.value)

    def keys(carrier: Headers): List[String] =
      carrier.headers.map(_.name.toString).distinct

  }

}
