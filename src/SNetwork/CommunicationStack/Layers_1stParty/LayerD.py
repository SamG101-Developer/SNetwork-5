from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket
from threading import Thread
from typing import TYPE_CHECKING
import pickle, secrets

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import Connection, LayerN, LayerNProtocol, RawRequest
from SNetwork.Config import CONNECTION_TOKEN_LENGTH
from SNetwork.Managers.DirectoryServiceManager import DirectoryServiceManager
from SNetwork.QuantumCrypto.Certificate import X509, X509Certificate, X509CertificateSigningRequest
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Bool, Optional, Bytes, Int

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack


class LayerDProtocol(LayerNProtocol, Enum):
    CertificateRequest = 0x01
    CertificateResponse = 0x02
    InvalidCertificateRequest = 0x03


@dataclass(kw_only=True)
class CertificateRequest(RawRequest):
    certificate_signing_request: X509CertificateSigningRequest


@dataclass(kw_only=True)
class CertificateResponse(RawRequest):
    certificate: X509Certificate


@dataclass(kw_only=True)
class InvalidCertificateRequest(RawRequest):
    identifier: Bytes
    public_key: Bytes


class LayerD(LayerN):
    """
    Layer D isn't part of the connection stack, but is used for communicating to the directory service. This is used for
    bootstrapping and getting node information when the distributed hash table fails to provide the information. As it
    follows the same API as other layers, it is designated as an unnumbered layer.

    The directory service will use this layer too, and no other stack, to talk back to the nodes, for things such as
    certificate generation, etc. The static key pair will contain both the secret and public key for the directory node
    if this class is instantiated from the directory node; otherwise only the public key will be known and present.
    """

    _this_identifier: Optional[Bytes]
    _this_static_key_pair: Optional[AsymmetricKeyPair]
    _is_directory_service: Bool
    _waiting_for_certificate: Bool
    _certificate: Optional[X509Certificate]

    def __init__(self, stack: CommunicationStack, socket: Socket, is_directory_service: Bool, this_identifier: Optional[Bytes] = None, this_static_key_pair: Optional[AsymmetricKeyPair] = None) -> None:
        super().__init__(stack, None, LayerDProtocol, socket, isolated_logger(LoggerHandlers.LAYER_D))
        self._stack._layerD = self

        self._this_identifier = this_identifier
        self._this_static_key_pair = this_static_key_pair
        self._is_directory_service = is_directory_service
        self._waiting_for_certificate = False
        self._certificate = None

        # Start listening on the socket for this layer.
        self._logger.debug("Layer D Ready")

    def join_network(self) -> None:
        # Choose a random directory service to connect to.
        d_address, d_port, d_identifier = DirectoryServiceManager.get_random_directory_service()
        self._logger.debug(f"Contacting DS at {d_address}:{d_port}.")

        # Create a temporary, unencrypted connection to the directory service.
        temp_connection = Connection(
            that_address=d_address, that_port=d_port,
            that_identifier=d_identifier, connection_token=secrets.token_bytes(CONNECTION_TOKEN_LENGTH))

        # Create an asymmetric key pair, and an identifier based on the public key.
        self._this_static_key_pair = QuantumSign.generate_key_pair()
        self._this_identifier = Hasher.hash(self._this_static_key_pair.public_key, HashAlgorithm.SHA3_256)

        # Create a certificate singing request for the directory service.
        this_certificate_signing_request = X509.generate_certificate_signing_request(
            client_identifier=self._this_identifier,
            client_secret_key=self._this_static_key_pair.secret_key,
            client_public_key=self._this_static_key_pair.public_key,
            directory_service_identifier=d_identifier)
        self._logger.debug("Certificate Request Created")

        # Package the information into a request for the directory service.
        self._waiting_for_certificate = True
        self._send(temp_connection, CertificateRequest(certificate_signing_request=this_certificate_signing_request))
        self._logger.debug("Certificate Request Sent")

    def _handle_certificate_request(self, address: IPv6Address, port: Int, request: CertificateRequest) -> None:
        # Extract metadata and information from the request.
        metadata = request.request_metadata
        requester_identifier = request.certificate_signing_request.certificate_request_info.subject["common_name"]
        requester_public_key = request.certificate_signing_request.certificate_request_info.subject_pk_info["public_key"]
        requester_request_sig = request.certificate_signing_request.signature_value

        # Create a non-cached, 1-time connection.
        temp_connection = Connection(
            that_address=address, that_port=port,
            that_identifier=requester_identifier, connection_token=metadata.connection_token)

        # Ensure the public key and identifier match.
        if Hasher.hash(requester_public_key, HashAlgorithm.SHA3_256) != requester_identifier:
            self._send(temp_connection, InvalidCertificateRequest(identifier=requester_identifier, public_key=requester_public_key))
            return

        # Check their signature is valid.
        if not QuantumSign.verify(pkey=requester_public_key, sig=requester_request_sig, id_=self._this_identifier):
            self._send(temp_connection, InvalidCertificateRequest(identifier=requester_identifier, public_key=requester_public_key))
            return

        # Accept the request by signing the certificate.
        certificate = X509.generate_certificate(
            client_signing_request=request.certificate_signing_request,
            client_identifier=requester_identifier,
            directory_service_secret_key=self._this_static_key_pair.secret_key,
            directory_service_identifier=self._this_identifier)

        # Send the certificate back to the requester.
        self._send(temp_connection, CertificateResponse(certificate=certificate))

    def _handle_certificate_response(self, address: IPv6Address, port: Int, request: CertificateResponse) -> None:
        # Extract the certificate from the request.
        certificate: X509Certificate = request.certificate

        # Check the certificate was signed by the directory service.
        if not QuantumSign.verify(
                pkey=self._this_static_key_pair.public_key,
                sig=certificate.signature_value,
                id_=self._this_identifier):
            self._logger.error("Invalid certificate signature.")
            return

        # Check the identifier on the certificate matches the expected one (anti-tamper).
        if certificate.tbs_certificate.subject["common_name"] != self._this_identifier.hex():
            self._logger.error("Invalid certificate identifier.")
            return

        # Check the public key on the certificate matches the expected one (anti-tamper).
        if certificate.tbs_certificate.subject_pk_info["public_key"] != self._this_static_key_pair.public_key:
            self._logger.error("Invalid certificate public key.")
            return

        # Mark the bootstrap sequence as complete.
        self._certificate = certificate
        self._waiting_for_certificate = False

    def _handle_command(self, address: IPv6Address, port: Int, request: RawRequest) -> None:
        # Deserialize the request and call the appropriate handler.

        match request.request_metadata.protocol:

            # Directory service will handle a certificate request.
            case LayerDProtocol.CertificateRequest if self._is_directory_service:
                thread = Thread(target=self._handle_certificate_request, args=(address, port, request))
                thread.start()

            # Nodes will handle a certificate response.
            case LayerDProtocol.CertificateResponse if self._waiting_for_certificate:
                thread = Thread(target=self._handle_certificate_response, args=(address, port, request))
                thread.start()

            # Nodes will hande an invalid certificate request error.
            case LayerDProtocol.InvalidCertificateRequest if self._waiting_for_certificate:
                thread = Thread(target=self._handle_invalid_certificate_request, args=(address, port, request))
                thread.start()

            # Default case
            case _:
                self._logger.error(f"Invalid request received: {request.request_metadata.protocol}")
