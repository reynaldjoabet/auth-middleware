package auth
package mtls

import java.io.ByteArrayInputStream
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.MessageDigest

import cats.effect.Sync
import cats.syntax.traverse.*

import com.comcast.ip4s.{Cidr, IpAddress}
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation
import org.http4s.server.ServerRequestKeys
import org.http4s.Request
import org.typelevel.ci.*

/**
  * Source of the TLS client certificate for mutual-TLS certificate-bound access tokens (RFC 8705
  * §3). The middleware compares the certificate's SHA-256 thumbprint against the token's
  * `cnf.x5t#S256` confirmation claim.
  */
trait ClientCertificates[F[_]] {
  def extract(req: Request[F]): F[Option[X509Certificate]]
}

object ClientCertificates {

  /**
    * Read the client certificate from the TLS session — use this when this service terminates TLS
    * itself (e.g. Ember/Blaze with `wantClientAuth`).
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

  /**
    * Read a URL-encoded PEM client certificate from a header set by a TLS-terminating reverse proxy
    * (e.g. nginx `$ssl_client_escaped_cert`, HAProxy in `deploy/haproxy`).
    *
    * The header is read only when the request's TCP peer, the proxy itself, is inside one of
    * `trustedProxies` (CIDR blocks, RFC 4632). From any other peer it is ignored, as if absent, so
    * a certificate-bound token fails closed. Otherwise anyone who can reach the service around the
    * proxy, or through a second proxy that passes headers on, could satisfy certificate binding by
    * sending the stolen token's certificate, which is public, in the header themselves.
    *
    * The proxy must still delete any client-supplied copy of the header: the peer check proves the
    * request came through the proxy, not that the proxy wrote the header.
    *
    * An unparseable value is treated as no certificate, which also fails closed.
    */
  def fromForwardedHeader[F[_]: Sync](
      trustedProxies: List[Cidr[IpAddress]],
      headerName: CIString = ci"X-Forwarded-Client-Cert"
  ): ClientCertificates[F] = {
    require(
      trustedProxies.nonEmpty,
      "a forwarded client-certificate header needs the proxies it may come from"
    )
    new ClientCertificates[F] {
      def extract(req: Request[F]): F[Option[X509Certificate]] =
        Sync[F].delay(
          if (!req.remote.exists(peer => Mtls.isTrusted(peer.host, trustedProxies))) None
          else
            req.headers
              .get(headerName)
              .map(_.head.value)
              .flatMap(Mtls.urlDecode)
              .flatMap(Mtls.parsePem)
        )
    }
  }

}

object Mtls {

  /**
    * RFC 8705 thumbprint: base64url(SHA-256(DER-encoded certificate)), computed by the Nimbus SDK
    * (`X509CertUtils.computeSHA256Thumbprint`).
    */
  def thumbprint(cert: X509Certificate): String =
    X509CertificateConfirmation.of(cert).getValue.toString

  /**
    * Constant-time comparison of a presented certificate against `cnf.x5t#S256`. Fails closed
    * (returns false) if the certificate cannot be thumbprinted.
    */
  def matches(
      cert: X509Certificate,
      expectedX5tS256: CertificateThumbprint
  ): Boolean =
    Option(X509CertificateConfirmation.of(cert).getValue).exists { tp =>
      MessageDigest.isEqual(
        tp.toString.getBytes(StandardCharsets.US_ASCII),
        (expectedX5tS256.value: String).getBytes(StandardCharsets.US_ASCII)
      )
    }

  /**
    * Whether `peer` is inside one of `cidrs`. An IPv4 peer seen on a dual-stack socket as an
    * IPv4-mapped IPv6 address (`::ffff:10.0.0.1`) is compared as IPv4; a block only matches
    * addresses of its own family.
    */
  private[auth] def isTrusted(peer: IpAddress, cidrs: List[Cidr[IpAddress]]): Boolean = {
    val address             = peer.collapseMappedV4
    def isV4(ip: IpAddress) = ip.fold(_ => true, _ => false)
    cidrs.exists(cidr => isV4(cidr.address) == isV4(address) && cidr.contains(address))
  }

  /**
    * CIDR blocks from a comma- or whitespace-separated list (`10.0.0.0/8, fd00::/8`). A bare
    * address is a single host (`/32` or `/128`). `Left` names the first entry that does not parse.
    */
  def parseCidrs(value: String): Either[String, List[Cidr[IpAddress]]] =
    value
      .split("[,\\s]+")
      .toList
      .filter(_.nonEmpty)
      .traverse { entry =>
        Cidr
          .fromString(entry)
          .orElse(IpAddress.fromString(entry).map(ip => Cidr(ip, ip.fold(_ => 32, _ => 128))))
          .toRight(s"'$entry' is not a CIDR block or IP address")
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
