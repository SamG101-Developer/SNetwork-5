from __future__ import annotations

import datetime as dt
import pickle
import secrets
from dataclasses import dataclass

from SNetwork.Config import TOLERANCE_CERTIFICATE_SIGNATURE
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign, SignedMessagePair
from SNetwork.Utils.Types import Bytes, Dict, Str, Bool


@dataclass(kw_only=True)
class X509CertificateSigningRequestInfo:
    subject: Dict[Str, Bytes]
    subject_pk_info: Dict[Str, Bytes]


@dataclass(kw_only=True)
class X509CertificateSigningRequest:
    certificate_request_info: X509CertificateSigningRequestInfo
    signature_algorithm: Dict[Str, Str]
    signature_value: SignedMessagePair


@dataclass(kw_only=True)
class X509TbsCertificate:
    version: str
    serial_number: int
    signature: Dict[Str, Str]
    issuer: Dict[Str, Bytes]
    issuer_pk_info: Dict[Str, Bytes]
    validity: Dict[Str, Str]
    subject: Dict[Str, Bytes]
    subject_pk_info: Dict[Str, Bytes]


@dataclass(kw_only=True)
class X509Certificate:
    tbs_certificate: X509TbsCertificate
    signature_algorithm: Dict[Str, Str]
    signature_value: SignedMessagePair


class X509:
    @staticmethod
    def generate_certificate_signing_request(
            client_identifier: Bytes,
            client_secret_key: Bytes,
            client_public_key: Bytes,
            signer_identifier: Bytes) -> X509CertificateSigningRequest:

        request_info = X509CertificateSigningRequestInfo(
            subject={"common_name": client_identifier},
            subject_pk_info={"public_key": client_public_key})

        request = X509CertificateSigningRequest(
            certificate_request_info=request_info,
            signature_algorithm={"algorithm": "dilithium4"},
            signature_value=QuantumSign.sign(skey=client_secret_key, msg=pickle.dumps(request_info), aad=signer_identifier))

        return request

    @staticmethod
    def generate_certificate(
            client_signing_request: X509CertificateSigningRequest,
            client_identifier: Bytes,
            directory_service_key_pair: AsymmetricKeyPair,
            signer_identifier: Bytes) -> X509Certificate:

        tbs_certificate = X509TbsCertificate(
            version="v3",
            serial_number=int.from_bytes(secrets.token_bytes(20)),
            signature={"algorithm": "dilithium4"},
            issuer={"common_name": signer_identifier},
            issuer_pk_info={"public_key": directory_service_key_pair.public_key},
            validity={
                "not_before": dt.datetime.now(dt.UTC).isoformat(),
                "not_after": (dt.datetime.now(dt.UTC) + dt.timedelta(seconds=TOLERANCE_CERTIFICATE_SIGNATURE)).isoformat()},
            subject=client_signing_request.certificate_request_info.subject,
            subject_pk_info={"public_key": client_signing_request.certificate_request_info.subject_pk_info["public_key"]})

        certificate = X509Certificate(
            tbs_certificate=tbs_certificate,
            signature_algorithm={"algorithm": "dilithium4"},
            signature_value=QuantumSign.sign(skey=directory_service_key_pair.secret_key, msg=pickle.dumps(tbs_certificate), aad=client_identifier))

        return certificate


def validate_certificate(certificate: X509Certificate) -> Bool:
    ...


__all__ = ["X509"]
