package auth

import java.io.ByteArrayInputStream
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.cert.{CertificateFactory, X509Certificate}

import cats.effect.Sync
import com.nimbusds.jose.util.Base64URL
import org.http4s.Request
import org.http4s.server.ServerRequestKeys
import org.typelevel.ci.*

/** Source of the TLS client certificate for mutual-TLS certificate-bound access
  * tokens (RFC 8705 §3). The middleware compares the certificate's SHA-256
  * thumbprint against the token's `cnf.x5t#S256` confirmation claim.
  */
trait ClientCertificates[F[_]] {
  def extract(req: Request[F]): F[Option[X509Certificate]]
}

object ClientCertificates {

  /** Read the client certificate from the TLS session — use this when this
    * service terminates TLS itself (e.g. Ember/Blaze with `wantClientAuth`).
    */
  def fromTlsSession[F[_]: Sync]: ClientCertificates[F] =
    new ClientCertificates[F] {
      def extract(req: Request[F]): F[Option[X509Certificate]] =
        Sync[F].delay(
          req.attributes
            .lookup(ServerRequestKeys.SecureSession)
            .flatten
            .flatMap(_.X509Certificate.headOption)
        )
    }

  /** Read a URL-encoded PEM client certificate from a header set by a
    * TLS-terminating reverse proxy (e.g. nginx `$ssl_client_escaped_cert`).
    *
    * SECURITY: only use this behind a proxy you control, and configure the
    * proxy to *always* set or strip this header. If clients can reach this
    * service directly, or the proxy forwards client-supplied values of the
    * header, an attacker can satisfy certificate binding by sending the stolen
    * token's certificate (public material) in the header. An unparseable value
    * is treated as no certificate, which fails closed for bound tokens.
    */
  def fromForwardedHeader[F[_]: Sync](
      headerName: CIString = ci"X-Forwarded-Client-Cert"
  ): ClientCertificates[F] = new ClientCertificates[F] {
    def extract(req: Request[F]): F[Option[X509Certificate]] =
      Sync[F].delay(
        req.headers
          .get(headerName)
          .map(_.head.value)
          .flatMap(Mtls.urlDecode)
          .flatMap(Mtls.parsePem)
      )
  }
}

object Mtls {

  /** RFC 8705 thumbprint: base64url(SHA-256(DER-encoded certificate)). */
  def thumbprint(cert: X509Certificate): String =
    Base64URL
      .encode(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded))
      .toString

  /** Constant-time comparison of a presented certificate against
    * `cnf.x5t#S256`.
    */
  def matches(cert: X509Certificate, expectedX5tS256: String): Boolean =
    try
      MessageDigest.isEqual(
        thumbprint(cert).getBytes(StandardCharsets.US_ASCII),
        expectedX5tS256.getBytes(StandardCharsets.US_ASCII)
      )
    catch {
      case _: java.security.cert.CertificateEncodingException => false
    }

  private[auth] def urlDecode(value: String): Option[String] =
    try Some(URLDecoder.decode(value, StandardCharsets.UTF_8))
    catch { case _: IllegalArgumentException => None }

  private[auth] def parsePem(pem: String): Option[X509Certificate] =
    try
      CertificateFactory
        .getInstance("X.509")
        .generateCertificate(
          new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8))
        ) match {
        case c: X509Certificate => Some(c)
        case _                  => None
      }
    catch {
      case _: java.security.cert.CertificateException => None
    }
}
