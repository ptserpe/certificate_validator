#! /usr/bin/env python3

import base64
import os
import socket
import ssl
import sys
from datetime import datetime
from urllib.parse import urljoin

import OpenSSL
import certifi
import requests
from OpenSSL import crypto
from OpenSSL.crypto import Error as OpenSSLCryptoError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import ocsp, DNSName, IPAddress
from cryptography.x509.ocsp import OCSPResponseStatus, OCSPCertStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

import utils


class ServerCert:
    """
    Class to perform different validations to the Server Certificate, namely self-signed check, expired, etc.
    """
    def __init__(self, x509cert: OpenSSL.SSL.X509) -> None:
        super().__init__()
        self.ocsp_server = None
        self.issuer = None
        self._cert = x509cert.to_cryptography()
        basic_constraints = self._cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        self.intermediate = basic_constraints.ca
        if self.intermediate:
            raise Exception("this is a CA certificate and not a server one")

    def _verify_self_signed(self):
        """
        method to check if the certificate is self-singed; not signed by a truster CA
        :return: bool that represents the above.
        """
        if self._cert.subject == self._cert.issuer:
            raise Exception("this is a self-signed certificate")

        aia = self._cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        issuers = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
        self.issuer = issuers[0].access_location.value if issuers else None

        ocsp_servers = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
        self.ocsp_server = ocsp_servers[0].access_location.value if ocsp_servers else None

        if self.issuer is None:
            self.intermediate = True

    def _verify_expired(self):
        """
        check if the server certificate hasn't expired
        """
        not_valid_after = self._cert.not_valid_after
        not_valid_before = self._cert.not_valid_before
        now = datetime.now()
        if not (not_valid_before <= now <= not_valid_after):
            raise Exception("the certificate has no valid date")

    def _verify_host(self, hostname):
        """
        check if the server certificate matches the host of the target url
        """
        if self.intermediate:
            return

        common_name = self._cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)
        if common_name is None:
            raise Exception("can't find the common name in the certificate")

        if utils.dnsname_match(common_name[0].value, hostname):
            return

        san = self._cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        ans = [an.value for an in san if isinstance(an, DNSName)]
        for an in ans:
            if utils.dnsname_match(an, hostname):
                return

        ans = [an.value for an in san if isinstance(an, IPAddress)]
        for an in ans:
            if utils.ipaddress_match(an, hostname):
                return

        raise Exception("certificate host mismatch")

    def _verify_revoked(self):
        """
        check if server certificate is revoked
        """
        if self.intermediate:
            return

        issuer_response = requests.get(self.issuer)
        if not issuer_response.ok:
            raise Exception(f'issuer cert get failed with response status: {issuer_response.status_code}')

        issuer_der = issuer_response.content
        issuer_pem = ssl.DER_cert_to_PEM_cert(issuer_der)
        issuer_cert = x509.load_pem_x509_certificate(issuer_pem.encode('ascii'), default_backend())

        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(self._cert, issuer_cert, SHA1())
        req = builder.build()
        req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
        url = urljoin(self.ocsp_server + '/', req_path.decode('ascii'))

        ocsp_resp = requests.get(url)
        if not ocsp_resp.ok:
            raise Exception(f'fetching ocsp cert status failed with response status: {ocsp_resp.status_code}')

        ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)
        if ocsp_decoded.response_status != OCSPResponseStatus.SUCCESSFUL:
            raise Exception(f'decoding ocsp response failed: {ocsp_decoded.response_status}')

        if ocsp_decoded.certificate_status != OCSPCertStatus.GOOD:
            raise Exception("the certificate is revoked")

    def verify(self, hostname):
        self._verify_expired()
        self._verify_host(hostname)
        self._verify_self_signed()
        self._verify_revoked()
        return True


class CertChain:

    def __init__(self, host, port=443) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.ssl_methods = [
            (OpenSSL.SSL.TLSv1_2_METHOD, "tlsv1.2"),
            (OpenSSL.SSL.TLSv1_1_METHOD, "tlsv1.1"),
            (OpenSSL.SSL.TLSv1_METHOD, "tlv1.0"),
            (OpenSSL.SSL.TLS_METHOD, "ssl")
        ]

    def _get_server_certificates(self) -> list[OpenSSL.SSL.X509]:
        """
        extract the chain of certificates from the host
        """
        try:
            for method in self.ssl_methods:
                try:
                    self.ctx = OpenSSL.SSL.Context(method=method[0])
                    self.ctx.load_verify_locations(certifi.where(), capath='/etc/ssl/certs')
                    connection = OpenSSL.SSL.Connection(self.ctx,
                                                        socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                    connection.set_tlsext_host_name(self.host.encode())
                    connection.settimeout(5)
                    connection.connect((self.host, self.port))
                    connection.setblocking(1)
                    connection.do_handshake()

                    self.method = method[0]

                    host_certs_chain = connection.get_peer_cert_chain()
                    if host_certs_chain is None:
                        raise Exception("couldn't find any certificates")

                    connection.close()
                    return host_certs_chain
                except OpenSSL.SSL.Error:
                    continue

            raise Exception("no appropriate handshake method found")

        except ConnectionError as e:
            raise Exception(f"can't connect to \"{self.host}:{self.port}\": {e}")

        except socket.gaierror as e:
            raise Exception(f"Unknown host \"{self.host}:{self.port}\": {e}")

    def _verify_chain(self, certs_chain: list[OpenSSL.crypto.x509]):
        """
        verify the chain of certificates using the build-in methods of OpenSSL
        """

        store = crypto.X509Store()
        store.set_flags(crypto.X509StoreFlags.X509_STRICT)
        store.load_locations(certifi.where(), capath='/etc/ssl/certs')

        server_cert = certs_chain[0]
        untrusted_certs = certs_chain[1:]

        try:
            crypto.X509StoreContext(store, server_cert, chain=untrusted_certs).verify_certificate()
        except crypto.X509StoreContextError as e:
            raise
        except OpenSSLCryptoError as e:
            if e.args == ([('x509 certificate routines', 'X509_STORE_add_cert', 'cert already in hash table')],):
                pass
            raise

    def verify(self):
        try:
            certs_chain = self._get_server_certificates()
        except Exception as e:
            raise Exception(f"err when download certificates chain: {e}")

        try:
            ServerCert(certs_chain[0]).verify(self.host)
        except Exception as e:
            raise Exception(f"err when verifying server certificate: {e}")

        try:
            self._verify_chain(certs_chain)
        except Exception as e:
            raise Exception(f"err when verifying certificates chain: {e}")


if __name__ == "__main__":
    len_argv = len(sys.argv)
    if len_argv < 2 or len_argv > 3:
        print(f"Usage: {os.path.basename(sys.argv[0])} hostname port[default=443]")
        sys.exit(2)

    host = sys.argv[1]
    port = 443

    if len(sys.argv) == 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("can't parse port")
            sys.exit(2)

    try:
        CertChain(host, port).verify()
    except Exception as e:
        print(f"connection to {host}:{port} is NOT secure: {e}")
        sys.exit(1)

    print(f"connection to {host}:{port} is secure")
