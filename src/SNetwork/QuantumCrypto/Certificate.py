from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from SNetwork.Crypt.AsymmetricKeys import PubKey, SecKey
from SNetwork.Crypt.Hash import SHA3_256
from SNetwork.Utils.Types import Bytes


class X509Certificate:
    _certificate: x509.Certificate

    def __init__(self, certificate: x509.Certificate) -> None:
        self._certificate = certificate

    @staticmethod
    def from_request(csr: X509CertificateSigningRequest, directory_service_secret_key: SecKey) -> X509Certificate:
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr._request.subject)
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Directory Service")]))
        builder = builder.public_key(csr._request.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.add_extension(csr._request.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value, critical=False)
        certificate = builder.sign(directory_service_secret_key._secret_key, SHA3_256())
        return X509Certificate(certificate)

    @staticmethod
    def from_der(der: Bytes) -> X509Certificate:
        return X509Certificate(x509.load_der_x509_certificate(der))

    @staticmethod
    def from_pem(pem: Bytes) -> X509Certificate:
        return X509Certificate(x509.load_pem_x509_certificate(pem))

    @property
    def der(self) -> Bytes:
        return self._certificate.public_bytes(Encoding.DER)

    @property
    def pem(self) -> Bytes:
        return self._certificate.public_bytes(Encoding.PEM)

    @property
    def public_key(self) -> PubKey:
        return PubKey(self._certificate.public_key())

    @property
    def subject(self) -> bytes:
        return self._certificate.subject.public_bytes()


class X509CertificateSigningRequest:
    _request: x509.CertificateSigningRequest

    def __init__(self, request: x509.CertificateSigningRequest) -> None:
        self._request = request

    @staticmethod
    def from_attributes(identifier: Bytes, secret_key: SecKey) -> X509CertificateSigningRequest:
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, identifier.decode())]))
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        request = builder.sign(secret_key._secret_key, SHA3_256())
        return X509CertificateSigningRequest(request)

    @staticmethod
    def from_der(der: Bytes) -> X509CertificateSigningRequest:
        return X509CertificateSigningRequest(x509.load_der_x509_csr(der))

    @staticmethod
    def from_pem(pem: Bytes) -> X509CertificateSigningRequest:
        return X509CertificateSigningRequest(x509.load_pem_x509_csr(pem))

    @property
    def der(self) -> Bytes:
        return self._request.public_bytes(Encoding.DER)

    @property
    def pem(self) -> Bytes:
        return self._request.public_bytes(Encoding.PEM)


__all__ = ["X509Certificate", "X509CertificateSigningRequest"]
