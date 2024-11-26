from __future__ import annotations
from typing import TypedDict
import datetime as dt, pickle, secrets

from SNetwork.QuantumCrypto.QuantumSign import QuantumSign
from SNetwork.Utils.Types import Bytes, Dict, Json, Str


class X509CertificateSigningRequestInfo(TypedDict):
    subject: Dict[Str, Bytes]
    subject_pk_info: Dict[Str, Bytes]


class X509CertificateSigningRequest(TypedDict):
    certificate_request_info: X509CertificateSigningRequestInfo
    signature_algorithm: Dict[Str, Str]
    signature_value: Bytes


class X509TbsCertificate(TypedDict):
    version: str
    serial_number: int
    signature: Dict[Str, Str]
    issuer: Dict[Str, Bytes]
    validity: Dict[Str, Str]
    subject: Dict[Str, Bytes]
    subject_public_key_info: Dict[Str, Bytes]


class X509Certificate(TypedDict):
    tbs_certificate: X509TbsCertificate
    signature_algorithm: Dict[Str, Str]
    signature_value: Bytes


class X509:
    @staticmethod
    def generate_certificate_signing_request(
            client_identifier: Bytes,
            client_secret_key: Bytes,
            client_public_key: Bytes,
            directory_service_identifier: Bytes) -> X509CertificateSigningRequest:

        request_info = X509CertificateSigningRequestInfo(
            subject={"common_name": client_identifier},
            subject_pk_info={"public_key": client_public_key})

        request = X509CertificateSigningRequest(
            certificate_request_info=request_info,
            signature_algorithm={"algorithm": "dilithium4"},
            signature_value=QuantumSign.sign(secret_key=client_secret_key, message=pickle.dumps(request_info), target_id=directory_service_identifier))

        return request

    @staticmethod
    def generate_certificate(
            client_signing_request: Json,
            client_identifier: Bytes,
            directory_service_secret_key: Bytes,
            directory_service_identifier: Bytes) -> X509Certificate:

        tbs_certificate = X509TbsCertificate(
            version="v3",
            serial_number=int.from_bytes(secrets.token_bytes(20)),
            signature={"algorithm": "dilithium4"},
            issuer={"common_name": directory_service_identifier},
            validity={
                "not_before": dt.datetime.now(dt.UTC).isoformat(),
                "not_after": (dt.datetime.now(dt.UTC) + dt.timedelta(days=365)).isoformat()},
            subject=client_signing_request["certificate_request_info"]["subject"],
            subject_public_key_info={"public_key": client_signing_request["certificate_request_info"]["subject_pk_info"]["public_key"]})

        certificate = X509Certificate(
            tbs_certificate=tbs_certificate,
            signature_algorithm={"algorithm": "dilithium4"},
            signature_value=QuantumSign.sign(
                secret_key=directory_service_secret_key,
                message=pickle.dumps(tbs_certificate),
                target_id=directory_service_identifier))

        return certificate


__all__ = ["X509"]
