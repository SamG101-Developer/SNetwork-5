from __future__ import annotations

import json
import random
from dataclasses import dataclass
from ipaddress import IPv6Address
from threading import Thread
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, RawRequest
from SNetwork.Config import PROFILE_CACHE, DIRECTORY_SERVICE_NODE_CACHE
from SNetwork.Managers.DirectoryServiceManager import DirectoryServiceManager
from SNetwork.Managers.KeyManager import KeyStoreData
from SNetwork.QuantumCrypto.Certificate import X509Certificate
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.QuantumCrypto.QuantumSign import SignedMessagePair, QuantumSign
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Socket import Socket
from SNetwork.Utils.Types import Optional, Bytes, Int, Tuple, List, Dict, Str

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack


class LayerD(LayerN):
    """
    Layer D isn't part of the connection stack, but is used for communicating to the directory service. This is used for
    bootstrapping and getting node information when the distributed hash table fails to provide the information. As it
    follows the same API as other layers, it is designated as an unnumbered layer.

    The directory service will use this layer too, and no other stack, to talk back to the nodes, for things such as
    sending IP/ID info, etc. The static key pair is required for to authenticate connections.
    """

    _self_id: Optional[Bytes]
    _self_cert: Optional[X509Certificate]
    _is_directory_service: Str
    _directory_service_static_key_pair: Optional[AsymmetricKeyPair]
    _directory_service_temp_map: Dict[Tuple[IPv6Address, Int], Bytes]
    _node_cache: List[Tuple[IPv6Address, Int, Bytes]]
    _node_cache_file: str

    @dataclass(kw_only=True)
    class BootstrapRequest(RawRequest):
        identifier: Bytes
        certificate: X509Certificate

    @dataclass(kw_only=True)
    class BootstrapResponse(RawRequest):
        node_info: List[Tuple[IPv6Address, Int, Bytes]]
        signature: SignedMessagePair

    def __init__(
            self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket, is_directory_service: Str,
            identifier: Bytes, certificate: X509Certificate,
            directory_service_static_key_pair: Optional[AsymmetricKeyPair] = None) -> None:

        super().__init__(stack, node_info, socket, isolated_logger(LoggerHandlers.LAYER_D))
        self._stack._layerD = self

        self._self_id = identifier
        self._self_cert = certificate
        self._is_directory_service = is_directory_service
        self._directory_service_static_key_pair = directory_service_static_key_pair
        self._directory_service_temp_map = {}
        self._node_cache = []
        self._node_cache_file = (
            PROFILE_CACHE % node_info.hashed_username.hex() if not is_directory_service else
            DIRECTORY_SERVICE_NODE_CACHE % self._is_directory_service)

        self._load_cache_from_file()

        # Start listening on the socket for this layer.
        self._logger.info("Layer D Ready")

    def _load_cache_from_file(self) -> None:
        # Load the cache from the file.
        with SafeFileOpen(self._node_cache_file, "r") as file:
            current_cache = json.load(file)

        # Convert the cache to a list of tuples.
        self._node_cache = [(IPv6Address(bytes.fromhex(node[0])), node[1], bytes.fromhex(node[2])) for node in current_cache.values()]
        self._node_cache = list(set(self._node_cache))

    def request_bootstrap(self) -> None:
        exclude = []

        for i in range(2):
            # Choose a random directory service to connect to.
            d_name, d_address, d_port, d_identifier, d_pkey = DirectoryServiceManager.get_random_directory_profile(exclude)
            self._directory_service_temp_map[(d_address, d_port)] = d_pkey
            self._logger.info(f"Contacting DS at {d_address}:{d_port} for boostrap.")
            exclude.append(d_name)

            # Create an encrypted connection to the directory service.
            conn = self._stack._layer4.connect(d_address, d_port, d_identifier)
            if not conn:
                self._logger.error("Failed to connect to the directory service.")
                return

            # Send the bootstrap request to the directory service.
            self._send_secure(conn, LayerD.BootstrapRequest(identifier=self._self_id, certificate=self._self_cert))

    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: RawRequest) -> None:
        # Deserialize the request and call the appropriate handler.

        match req:

            # Directory service will handle a bootstrap request.
            case LayerD.BootstrapRequest() if self._is_directory_service:
                thread = Thread(target=self._handle_bootstrap_request, args=(peer_ip, peer_port, req))
                thread.start()

            # Nodes will handle a bootstrap response.
            case LayerD.BootstrapResponse() if not self._is_directory_service:
                thread = Thread(target=self._handle_bootstrap_response, args=(peer_ip, peer_port, req))
                thread.start()

            # Default case
            case _:
                self._logger.error(f"Invalid request received: {req}")

    def _handle_bootstrap_request(self, peer_ip: IPv6Address, peer_port: Int, req: BootstrapRequest) -> None:
        # Extract the metadata from the request.
        conn = self._stack._layer4._conversations[req.conn_tok]

        # Cache this node and its associated information.
        self._node_cache.append((peer_ip, peer_port, req.identifier))

        # Choose some random nodes to send back.
        node_cache = random.sample(self._node_cache, min(5, len(self._node_cache)))
        signature  = QuantumSign.sign(skey=self._directory_service_static_key_pair.secret_key, msg=node_cache, aad=req.identifier)
        self._send_secure(conn, LayerD.BootstrapResponse(node_info=node_cache, signature=signature))

    def _handle_bootstrap_response(self, address: IPv6Address, port: Int, request: BootstrapResponse) -> None:
        # Check the signature of the response.
        d_pkey = self._directory_service_temp_map.get((address, port))
        if not QuantumSign.verify(pkey=d_pkey, sig=request.signature, aad=self._self_id):
            self._logger.error("Invalid signature in bootstrap response.")
            return

        # Add the nodes to the cache.
        self._node_cache.extend(request.node_info)
        self._logger.info(f"Extended node cache with {len(request.node_info)} nodes.")

        with SafeFileOpen(self._node_cache_file, "r") as file:
            current_cache = json.load(file)

        # Write the nodes to the cache.
        with SafeFileOpen(self._node_cache_file, "w") as file:
            current_cache |= {node_info[2].hex(): [node_info[0].packed.hex(), node_info[1], node_info[2].hex()] for node_info in request.node_info}
            json.dump(current_cache, file, indent=4)
