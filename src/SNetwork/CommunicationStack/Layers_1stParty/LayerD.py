from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket
from threading import Thread
from typing import TYPE_CHECKING
import secrets

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import Connection, LayerN, LayerNProtocol, AbstractRequest
from SNetwork.Config import DIRECTORY_ADDRESS, DIRECTORY_IDENTIFIER, CONNECTION_TOKEN_LENGTH, DIRECTORY_PORT
from SNetwork.Crypt.AsymmetricKeys import KeyPair
from SNetwork.QuantumCrypto.Certificate import X509CertificateSigningRequest, X509Certificate
from SNetwork.Crypt.Hash import Hasher, SHA3_256
from SNetwork.Crypt.Sign import Signer
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Json, Bool, Optional, Bytes, Int

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack


class LayerDProtocol(LayerNProtocol, Enum):
    CertificateRequest = 0x01
    CertificateResponse = 0x02
    InvalidCertificateRequest = 0x03


@dataclass(kw_only=True)
class CertificateRequest(AbstractRequest):
    identifier: Bytes
    public_key: Bytes
    certificate: Bytes


@dataclass(kw_only=True)
class CertificateResponse(AbstractRequest):
    certificate: Bytes


@dataclass(kw_only=True)
class InvalidCertificateRequest(AbstractRequest):
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
    _this_static_key_pair: Optional[KeyPair]
    _is_directory_service: Bool
    _waiting_for_certificate: Bool
    _certificate: Optional[X509Certificate]

    def __init__(self, stack: CommunicationStack, socket: Socket, is_directory_service: Bool, this_static_key_pair: Optional[KeyPair] = None) -> None:
        super().__init__(stack, None, socket, isolated_logger(LoggerHandlers.LAYER_D))

        self._this_identifier = None
        self._this_static_key_pair = this_static_key_pair
        self._is_directory_service = is_directory_service
        self._waiting_for_certificate = False
        self._certificate = None

        # Start listening on the socket for this layer.
        self._logger.debug("Layer D Ready")

    def join_network(self) -> None:
        # Create a temporary, unencrypted connection to the directory service.
        temp_connection = Connection(
            that_address=DIRECTORY_ADDRESS,
            that_port=DIRECTORY_PORT,
            that_identifier=DIRECTORY_IDENTIFIER,
            connection_token=secrets.token_bytes(CONNECTION_TOKEN_LENGTH))

        # Create an asymmetric key pair, and an identifier based on the public key.
        this_static_key_pair = Signer.generate_key_pair()
        this_unique_identifier = Hasher.hash(this_static_key_pair.public_key.der, SHA3_256())

        # Create a certificate singing request for the directory service.
        this_certificate_request = X509CertificateSigningRequest.from_attributes(
            identifier=this_unique_identifier,
            secret_key=this_static_key_pair.secret_key)

        # Package the information into a request for the directory service.
        self._waiting_for_certificate = True
        self._send(temp_connection, CertificateRequest(
            identifier=this_unique_identifier,
            public_key=this_static_key_pair.public_key.der,
            certificate=this_certificate_request.der))

    def _handle_certificate_request(self, address: IPv6Address, port: Int, request: CertificateRequest) -> None:
        # Extract metadata from the request and create a non-cached, 1-time connection.
        certificate_request = X509CertificateSigningRequest.from_der(request.certificate)
        temp_connection = Connection(
            that_address=address,
            that_port=port,
            that_identifier=request.identifier,
            connection_token=request.connection_token)

        # Ensure the public key and identifier match.
        if Hasher.hash(request.public_key, SHA3_256()) != request.identifier:
            self._send(temp_connection, InvalidCertificateRequest(
                identifier=request.identifier,
                public_key=request.public_key))

        # Create the signed certificate, and send it back to the requester.
        certificate = X509Certificate.from_request(certificate_request, self._this_static_key_pair.secret_key)
        self._send(temp_connection, CertificateResponse(
            certificate=certificate.der))

    def _handle_certificate_response(self, address: IPv6Address, port: Int, request: CertificateResponse) -> None:
        # Extract the certificate from the request.
        certificate = X509Certificate.from_der(request.certificate)

        # Check the certificate was signed by the directory service.
        ...

        # Check the identifier on the certificate matches the expected one (anti-tamper).
        if certificate.subject != self._this_identifier:
            self._logger.error("Invalid certificate identifier.")
            return

        # Check the public key on the certificate matches the expected one (anti-tamper).
        if certificate.public_key.der != self._this_static_key_pair.public_key.der:
            self._logger.error("Invalid certificate public key.")
            return

        # Mark the bootstrap sequence as complete.
        self._certificate = certificate

    def _handle_command(self, address: IPv6Address, port: Int, data: Json) -> None:
        # Deserialize the request and call the appropriate handler.
        request_type = globals()[LayerDProtocol(data["protocol"]).name]
        request = request_type.deserialize(data)

        match request.protocol:

            # Directory service will handle a certificate request.
            case LayerDProtocol.CertificateRequest.value if self._is_directory_service:
                thread = Thread(target=self._handle_certificate_request, args=(address, port, request))
                thread.start()

            # Nodes will handle a certificate response.
            case LayerDProtocol.CertificateResponse.value if self._waiting_for_certificate:
                thread = Thread(target=self._handle_certificate_response, args=(address, port, request))
                thread.start()

            # Nodes will hande an invalid certificate request error.
            case LayerDProtocol.InvalidCertificateRequest.value if self._waiting_for_certificate:
                thread = Thread(target=self._handle_invalid_certificate_request, args=(address, port, request))
                thread.start()

    def _send(self, connection: Connection, request: AbstractRequest) -> None:
        protocol = LayerDProtocol(request.__class__.__name__)
        pass
