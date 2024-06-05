"""
This file implement the ssl checker class
"""
import base64
import ssl
import socket
import requests
from datetime import date

from dateutil import parser
from urllib.parse import urljoin

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

import ssl_checker.exception as SslExceptions

class SslChecker():
    """SSL Checker
    """

    def __init__(self):
        # Define the SSL session context
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE


    def _get_cert_for_hostname(self, hostname, port):
        try:
            conn = ssl.create_connection((hostname, port))
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(conn, server_hostname=hostname)
            certDER = sock.getpeercert(True)
            certPEM = ssl.DER_cert_to_PEM_cert(certDER)
            return x509.load_pem_x509_certificate(certPEM.encode('ascii'), default_backend())
        except Exception as exc:
            raise SslExceptions.HostCertificateError("Cannot get the domain certificate") from exc

    def _is_self_signed(self, cert):
        # Check if the subject and issuer are the same
        return cert.subject == cert.issuer

    def _get_issuer(self, cert):
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            issuers = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
            if not issuers:
                raise SslExceptions.NoIssuersEntry()
            return issuers[0].access_location.value
        except Exception as exc:
            raise SslExceptions.IssuerError("Cannot get Issuer") from exc

    def _get_ocsp_server(self, cert):
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
            if not ocsps:
                raise SslExceptions.OCSPError("Cannot get OCSP Server")
            return ocsps[0].access_location.value
        except Exception() as exc:
            raise SslExceptions.OCSPError("Cannot get OCSP Server") from exc

    def _get_issuer_cert(self, ca_issuer):
        try:
            issuer_response = requests.get(ca_issuer)
            if issuer_response.ok:
                issuerDER = issuer_response.content
                issuerPEM = ssl.DER_cert_to_PEM_cert(issuerDER)
                return x509.load_pem_x509_certificate(issuerPEM.encode('ascii'), default_backend())
        except Exception() as exc:
            raise SslExceptions.IssuerError("Cannot get Issuer Certificate") from exc

        raise SslExceptions.IssuerError("Cannot get Issuer Certificate")

    def _get_ocsp_request(self, ocsp_server, cert, issuer_cert):
        try:
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, SHA256())
            req = builder.build()
            req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
            return urljoin(ocsp_server + '/', req_path.decode('ascii'))
        except Exception as exc:
            raise SslExceptions.OCSPError("Cannot Build the OCSP Request") from exc

    def _get_ocsp_cert_status(self, ocsp_server, cert, issuer_cert):
        try:
            ocsp_resp = requests.get(self._get_ocsp_request(ocsp_server, cert, issuer_cert))
            if ocsp_resp.ok:
                ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)
                if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
                    return ocsp_decoded.certificate_status
                raise SslExceptions.OCSPError(f'Decoding OCSP response failed: {ocsp_decoded.response_status}')
        except Exception as exc:
            raise SslExceptions.OCSPError("Cannot get OCSP Certificate Status") from exc
        raise SslExceptions.OCSPError(f'Fetching OCSP cert status failed with response status: {ocsp_resp.status_code}')

    def _get_cert_status_for_host(self, hostname, port):
        print('Hostname:', hostname, "Port:", port)
        cert = self._get_cert_for_hostname(hostname, port)
        if self._is_self_signed(cert):
            return 'Self-signed'
        ca_issuer = self._get_issuer(cert)
        print('Issuer:', ca_issuer)
        issuer_cert = self._get_issuer_cert(ca_issuer)
        ocsp_server = self._get_ocsp_server(cert)
        print('OCSP Server:', ocsp_server)
        return self._get_ocsp_cert_status(ocsp_server, cert, issuer_cert)

    def get_cert_details(self, domain):
        """
        Get Certificate details
        """

        cert = self._get_cert_for_hostname(hostname=domain, port=443)
        subject = cert.subject.rfc4514_string()
        expiration = cert.not_valid_after_utc
        try:
            status = self._get_cert_status_for_host(hostname=domain, port=443)
        except Exception:
            status = None

        certificate_details = {
                                "domain": domain,
                                "subject": subject,
                                "expiration": expiration,
                                "status": status
                              }

        return certificate_details
