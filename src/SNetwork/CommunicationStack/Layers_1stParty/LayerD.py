from __future__ import annotations

import pickle
import random
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket
from threading import Thread
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, LayerNProtocol, RawRequest
from SNetwork.Config import PROFILE_CACHE
from SNetwork.Managers.DirectoryServiceManager import DirectoryServiceManager
from SNetwork.QuantumCrypto.Certificate import X509Certificate
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.QuantumCrypto.QuantumSign import SignedMessagePair, QuantumSign
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Bool, Optional, Bytes, Int, Tuple, List

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack


class LayerDProtocol(LayerNProtocol, Enum):
    BootstrapRequest = 0x05
    BootstrapResponse = 0x06


@dataclass(kw_only=True)
class BootstrapRequest(RawRequest):
    identifier: Bytes
    certificate: X509Certificate


@dataclass(kw_only=True)
class BootstrapResponse(RawRequest):
    node_info: List[Tuple[IPv6Address, Int, Bytes]]
    signature: SignedMessagePair


class LayerD(LayerN):
    """
    Layer D isn't part of the connection stack, but is used for communicating to the directory service. This is used for
    bootstrapping and getting node information when the distributed hash table fails to provide the information. As it
    follows the same API as other layers, it is designated as an unnumbered layer.

    The directory service will use this layer too, and no other stack, to talk back to the nodes, for things such as
    sending IP/ID info, etc. The static key pair is required for to authenticate connections.
    """

    _identifier: Optional[Bytes]
    _is_directory_service: Bool
    _directory_service_static_key_pair: Optional[AsymmetricKeyPair]
    _certificate: Optional[X509Certificate]
    _node_cache: List[Tuple[IPv6Address, Int, Bytes]]

    _waiting_for_bootstrap: Bool

    def __init__(
            self, stack: CommunicationStack, socket: Socket, is_directory_service: Bool, identifier: Bytes,
            certificate: X509Certificate, directory_service_static_key_pair: Optional[AsymmetricKeyPair] = None) -> None:

        super().__init__(stack, None, LayerDProtocol, socket, isolated_logger(LoggerHandlers.LAYER_D))
        self._stack._layerD = self

        self._identifier = identifier
        self._is_directory_service = is_directory_service
        self._directory_service_static_key_pair = directory_service_static_key_pair
        self._certificate = certificate

        self._node_cache = []
        self._waiting_for_bootstrap = False

        # Start listening on the socket for this layer.
        self._logger.info("Layer D Ready")

    def request_bootstrap(self) -> None:
        # Choose a random directory service to connect to.
        d_address, d_port, d_identifier, d_pkey = DirectoryServiceManager.get_random_directory_profile()
        self._directory_service_static_key_pair = AsymmetricKeyPair(public_key=d_pkey)
        self._logger.info(f"Contacting DS at {d_address}:{d_port}.")

        # Create an encrypted connection to the directory service.
        connection = self._stack._layer4.connect(d_address, d_port, d_identifier)
        if not connection:
            self._logger.error("Failed to connect to the directory service.")
            return

        # Send the bootstrap request to the directory service.
        self._waiting_for_bootstrap = True
        self._send_secure(connection, BootstrapRequest(identifier=self._identifier, certificate=self._certificate))

    def _handle_bootstrap_request(self, address: IPv6Address, port: Int, request: BootstrapRequest) -> None:
        # Extract the metadata from the request.
        metadata = request.request_metadata
        connection = self._stack._layer4._conversations[metadata.connection_token]

        # Cache this node and its associated information.
        self._node_cache.append((address, port, request.identifier))

        # Choose some random nodes to send back.
        node_cache = random.sample(self._node_cache, 5)
        signature  = QuantumSign.sign(skey=self._directory_service_static_key_pair.secret_key, msg=node_cache, aad=request.identifier)
        self._send_secure(connection, BootstrapResponse(node_info=node_cache, signature=signature))

    def _handle_bootstrap_response(self, address: IPv6Address, port: Int, request: BootstrapResponse) -> None:
        # Check the signature of the response.
        if not QuantumSign.verify(pkey=self._directory_service_static_key_pair.public_key, sig=request.signature, aad=self._identifier):
            self._logger.error("Invalid signature in bootstrap response.")
            return

        # Add the nodes to the cache.
        self._node_cache.extend(request.node_info)
        self._waiting_for_bootstrap = False

        # Write the nodes to the cache.
        with SafeFileOpen(PROFILE_CACHE % self._identifier.hex(), "wb") as file:
            pickle.dump(self._node_cache, file)

    def _handle_command(self, address: IPv6Address, port: Int, request: RawRequest) -> None:
        # Deserialize the request and call the appropriate handler.

        match request.request_metadata.protocol:
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
