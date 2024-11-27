from __future__ import annotations

import random
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket
from threading import Thread
from typing import TYPE_CHECKING
import pickle, secrets

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import Connection, LayerN, LayerNProtocol, RawRequest
from SNetwork.Config import CONNECTION_TOKEN_LENGTH, PROFILE_CACHE
from SNetwork.Managers.DirectoryServiceManager import DirectoryServiceManager
from SNetwork.QuantumCrypto.Certificate import X509, X509Certificate, X509CertificateSigningRequest
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign, SignedMessagePair
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Bool, Optional, Bytes, Int, Tuple, List, Dict

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack


class LayerDProtocol(LayerNProtocol, Enum):
    CertificateRequest = 0x01
    CertificateResponse = 0x02
    InvalidCertificateRequest = 0x03
    OkCertificateRequest = 0x04
    BootstrapRequest = 0x05
    BootstrapResponse = 0x06


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


@dataclass(kw_only=True)
class OkCertificateRequest(RawRequest):
    identifier: Bytes
    certificate: X509Certificate
    signature: SignedMessagePair


@dataclass(kw_only=True)
class BootstrapRequest(RawRequest):
    pass


@dataclass(kw_only=True)
class BootstrapResponse(RawRequest):
    node_info: List[Tuple[IPv6Address, Int, Bytes, Bytes]]


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
    _directory_service_static_public_key: Optional[Bytes]
    _certificate: Optional[X509Certificate]
    _node_cache: List[Tuple[IPv6Address, Int, Bytes, Bytes]]
    _certificate_cache: Dict[Bytes, X509Certificate]

    _waiting_for_bootstrap: Bool
    _waiting_for_certificate: Bool

    def __init__(self, stack: CommunicationStack, socket: Socket, is_directory_service: Bool, this_identifier: Optional[Bytes] = None, this_static_key_pair: Optional[AsymmetricKeyPair] = None) -> None:
        super().__init__(stack, None, LayerDProtocol, socket, isolated_logger(LoggerHandlers.LAYER_D))
        self._stack._layerD = self

        self._this_identifier = this_identifier
        self._this_static_key_pair = this_static_key_pair
        self._is_directory_service = is_directory_service
        self._directory_service_static_public_key = None
        self._certificate = None

        self._node_cache = []
        self._certificate_cache = {}

        self._waiting_for_bootstrap = False
        self._waiting_for_certificate = False

        # Start listening on the socket for this layer.
        self._logger.info("Layer D Ready")

    def join_network(self) -> None:
        # Choose a random directory service to connect to.
        d_address, d_port, d_identifier, d_pkey = DirectoryServiceManager.get_random_directory_service()
        self._directory_service_static_public_key = d_pkey

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

        # Package the information into a request for the directory service.
        self._waiting_for_certificate = True
        self._send(temp_connection, CertificateRequest(certificate_signing_request=this_certificate_signing_request))

    def request_bootstrap(self) -> None:
        # Choose a random directory service to connect to.
        d_address, d_port, d_identifier, d_pkey = DirectoryServiceManager.get_random_directory_service()
        self._directory_service_static_public_key = d_pkey
        self._logger.info(f"Contacting DS at {d_address}:{d_port}.")

        # Create an encrypted connection to the directory service.
        connection = self._stack._layer4.connect(d_address, d_port, d_identifier)
        if not connection:
            self._logger.error("Failed to connect to the directory service.")
            return

        # Send the bootstrap request to the directory service.
        self._waiting_for_bootstrap = True
        self._send_secure(connection, BootstrapRequest())

    def _handle_certificate_request(self, address: IPv6Address, port: Int, request: CertificateRequest) -> None:
        # Extract metadata and information from the request.
        metadata = request.request_metadata
        requester_id = request.certificate_signing_request.certificate_request_info.subject["common_name"]
        requester_pkey = request.certificate_signing_request.certificate_request_info.subject_pk_info["public_key"]
        requester_request_sig = request.certificate_signing_request.signature_value

        # Create a non-cached, 1-time connection.
        temp_connection = Connection(
            that_address=address, that_port=port,
            that_identifier=requester_id, connection_token=metadata.connection_token)

        # Ensure the public key and identifier match.
        if Hasher.hash(requester_pkey, HashAlgorithm.SHA3_256) != requester_id:
            self._send(temp_connection, InvalidCertificateRequest(identifier=requester_id, public_key=requester_pkey))
            return

        # Check their signature is valid.
        if not QuantumSign.verify(pkey=requester_pkey, sig=requester_request_sig, id_=self._this_identifier):
            self._send(temp_connection, InvalidCertificateRequest(identifier=requester_id, public_key=requester_pkey))
            return

        # Accept the request by signing the certificate.
        certificate = X509.generate_certificate(
            client_signing_request=request.certificate_signing_request,
            client_identifier=requester_id,
            directory_service_key_pair=self._this_static_key_pair,
            directory_service_identifier=self._this_identifier)
        self._certificate_cache[requester_id] = certificate

        # Send the certificate back to the requester.
        self._send(temp_connection, CertificateResponse(certificate=certificate))

    def _handle_certificate_response(self, address: IPv6Address, port: Int, request: CertificateResponse) -> None:
        # Extract the certificate from the request.
        certificate: X509Certificate = request.certificate
        d_identifier = certificate.tbs_certificate.issuer["common_name"]
        directory_service_pkey = self._directory_service_static_public_key
        directory_service_cert_sig = certificate.signature_value

        # Check the certificate was signed by the directory service.
        if not QuantumSign.verify(pkey=directory_service_pkey, sig=directory_service_cert_sig, id_=self._this_identifier):
            self._logger.error("Invalid certificate signature.")
            return

        # Check the identifier on the certificate matches the expected one (anti-tamper).
        if certificate.tbs_certificate.subject["common_name"] != self._this_identifier:
            self._logger.error("Invalid certificate identifier.")
            return

        # Check the public key on the certificate matches the expected one (anti-tamper).
        if certificate.tbs_certificate.subject_pk_info["public_key"] != self._this_static_key_pair.public_key:
            self._logger.error("Invalid certificate public key.")
            return

        # Mark the bootstrap sequence as complete.
        self._certificate = certificate
        self._waiting_for_certificate = False
        self._logger.info("Certificate received.")

        # Wait for the node to initialize the other layers.
        while not self._stack._layer4: continue

        # Send an OK response to the directory service.
        connection = self._stack._layer4.connect(address, port, d_identifier)
        if not connection:
            self._logger.error("Failed to connect to the directory service.")
            return

        self._send_secure(connection, OkCertificateRequest(
            identifier=self._this_identifier,
            certificate=certificate,
            signature=QuantumSign.sign(skey=self._this_static_key_pair.secret_key, msg=pickle.dumps(certificate), id_=self._this_identifier)))
        self._logger.info("Sent OK certificate.")

    def _handle_invalid_certificate_request(self, address: IPv6Address, port: Int, request: InvalidCertificateRequest) -> None:
        self._logger.error(f"Certificate request was invalid.")
        self._waiting_for_certificate = False

    def _handle_ok_certificate_request(self, address: IPv6Address, port: Int, request: OkCertificateRequest) -> None:
        # Extract the metadata from the request.
        metadata = request.request_metadata
        connection = self._stack._layer4._conversations[metadata.connection_token]

        # Check the signature is valid.
        if not QuantumSign.verify(pkey=request.certificate.tbs_certificate.subject_pk_info["public_key"], sig=request.signature, id_=request.identifier):
            self._logger.error("Invalid signature.")
            return

        # Check the certificate has been cached as pending.
        if request.identifier not in self._certificate_cache.keys():
            self._logger.error("Certificate was not cached.")
            return

        # Check the certificate is valid.
        if request.certificate != self._certificate_cache[request.identifier]:
            self._logger.error("Certificate was invalid.")
            return

        # Add the certificate to the cache.
        self._node_cache.append((address, port, request.identifier, request.certificate.tbs_certificate.subject_pk_info["public_key"]))
        del self._certificate_cache[request.identifier]

        # Log the certificate.
        self._logger.info(f"Certificate for {request.identifier.hex()} okayed.")

    def _handle_bootstrap_request(self, address: IPv6Address, port: Int, request: BootstrapRequest) -> None:
        # Extract the metadata from the request.
        metadata = request.request_metadata
        connection = self._stack._layer4._conversations[metadata.connection_token]

        # Choose some random nodes to send back.
        node_cache = random.sample(self._node_cache, 5)
        self._send_secure(connection, BootstrapResponse(node_info=node_cache))

    def _handle_bootstrap_response(self, address: IPv6Address, port: Int, request: BootstrapResponse) -> None:
        # Extract the metadata from the request.
        metadata = request.request_metadata
        connection = self._stack._layer4._conversations[metadata.connection_token]

        # Add the nodes to the cache.
        self._node_cache.extend(request.node_info)
        self._waiting_for_bootstrap = False

        # Write the nodes to the cache.
        with SafeFileOpen(PROFILE_CACHE % self._this_identifier.hex(), "wb") as file:
            pickle.dump(self._node_cache, file)

    def _handle_command(self, address: IPv6Address, port: Int, request: RawRequest) -> None:
        # Deserialize the request and call the appropriate handler.

        match request.request_metadata.protocol:

            # Directory service will handle a certificate request.
            case LayerDProtocol.CertificateRequest if self._is_directory_service:
                thread = Thread(target=self._handle_certificate_request, args=(address, port, request))
                thread.start()

            # Nodes will handle a certificate response.
            case LayerDProtocol.CertificateResponse if not self._is_directory_service and self._waiting_for_certificate:
                thread = Thread(target=self._handle_certificate_response, args=(address, port, request))
                thread.start()

            # Nodes will hande an invalid certificate request error.
            case LayerDProtocol.InvalidCertificateRequest if not self._is_directory_service and self._waiting_for_certificate:
                thread = Thread(target=self._handle_invalid_certificate_request, args=(address, port, request))
                thread.start()

            # Directory service will handle an OK certificate request.
            case LayerDProtocol.OkCertificateRequest if self._is_directory_service:
                thread = Thread(target=self._handle_ok_certificate_request, args=(address, port, request))
                thread.start()

            # Directory service will handle a bootstrap request.
            case LayerDProtocol.BootstrapRequest if self._is_directory_service:
                thread = Thread(target=self._handle_bootstrap_request, args=(address, port, request))
                thread.start()

            # Nodes will handle a bootstrap response.
            case LayerDProtocol.BootstrapResponse if not self._is_directory_service and self._waiting_for_bootstrap:
                thread = Thread(target=self._handle_bootstrap_response, args=(address, port, request))
                thread.start()

            # Default case
            case _:
                self._logger.error(f"Invalid request received: {request.request_metadata.protocol}")
