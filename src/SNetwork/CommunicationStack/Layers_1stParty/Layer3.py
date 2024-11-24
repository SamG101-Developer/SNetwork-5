from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket
from threading import Lock, Thread
from typing import TYPE_CHECKING
import math, operator, random, time

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, LayerNProtocol, Connection, InsecureRequest
from SNetwork.CommunicationStack.Isolation import strict_isolation
from SNetwork.Config import DHT_STORE_PATH, DHT_ALPHA, DHT_K_VALUE, DHT_KEY_LENGTH
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Logger import LoggerHandlers, isolated_logger
from SNetwork.Utils.Types import Bool, Dict, Int, Json, Bytes, List, Optional, Tuple, Float, Str

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.Managers.KeyManager import KeyStoreData


type KBucket = List[Connection]
type KBuckets = List[KBucket]


def node_distance(a: Bytes, b: Bytes) -> Int:
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


@dataclass(kw_only=True)
class NodeLookupRequest:
    target_node_identifier: Bytes
    current_closest: Optional[Connection]
    lock: Lock = field(init=False, default_factory=Lock)
    queried_nodes: List[Connection] = field(init=False, default_factory=list)

    @property
    def closest_distance(self) -> Int:
        return node_distance(self.target_node_identifier, self.current_closest.that_identifier)


class Layer3Protocol(LayerNProtocol, Enum):
    PingRequest = 0x00
    PongResponse = 0x01
    PutResourceRequest = 0x02
    GetResourceRequest = 0x03
    ReturnResourcePassResponse = 0x04
    ReturnResourceFailResponse = 0x05
    FindNodeRequest = 0x06
    FindNodeResponse = 0x07


@dataclass(kw_only=True)
class PingRequest(InsecureRequest):
    ping_timestamp: Float


@dataclass(kw_only=True)
class PongResponse(InsecureRequest):
    ping_timestamp: Float


@dataclass(kw_only=True)
class PutResourceRequest(InsecureRequest):
    resource_key: Bytes
    resource_value: Bytes


@dataclass(kw_only=True)
class GetResourceRequest(InsecureRequest):
    resource_key: Bytes


@dataclass(kw_only=True)
class ReturnResourcePassResponse(InsecureRequest):
    resource_key: Bytes
    resource_value: Bytes


@dataclass(kw_only=True)
class ReturnResourceFailResponse(InsecureRequest):
    resource_key: Bytes
    closest_node_identifiers: List[Bytes]
    closest_node_addresses: List[Tuple[Str, Int]]


@dataclass(kw_only=True)
class FindNodeRequest(InsecureRequest):
    target_identifier: Bytes


@dataclass(kw_only=True)
class FindNodeResponse(InsecureRequest):
    target_identifier: Bytes
    closest_nodes_identifiers: List[Bytes]
    closest_nodes_addresses: List[Tuple[Str, Int]]


class Layer3(LayerN):
    """
    Layer 3 of the Communication Stack is the "Distributed Layer". This layer is responsible for traversing the DHT and
    finding the closest nodes to a target node. It is also responsible for storing and retrieving resources from the
    DHT.

    Data sent in this layer authenticated-encrypted, as the connections must be established securely from Layer 4,
    before any data is sent.

    Attributes:
        _this_identifier: The identifier of this node.
        _k_buckets: The list of k-buckets, each containing a list of connections.
        _ping_queue: The list of connections that have been pinged.
        _stored_keys: The list of keys stored in the DHT.
        _node_lookup_requests: The list of node lookup requests.

    Methods:
        join_distributed_hash_table_network: Joins the DHT network.
        get_resource: Retrieves a resource from the DHT.
        put_resource: Stores a resource in the DHT.
        _handle_command: Handles a command received from a remote node.
        _node_lookup: Initiates a node lookup request.
        _recursive_search: Recursively searches for a resource in the DHT.
        _update_k_buckets: Updates the k-buckets with a new node.
        _closest_k_nodes_to: Returns the k closest nodes to a target identifier.
        _handle_ping_request: Handles a ping request.
        _handle_pong_response: Handles a pong response.
        _handle_put_resource_request: Handles a put resource request.
        _handle_get_resource_request: Handles a get resource request.
        _handle_return_resource_response: Handles a return resource response.
        _handle_find_node_request: Handles a find node request.
        _handle_find_node_response: Handles a find node response.
        _all_known_nodes: Returns all known nodes in the DHT (flattens k_buckets).
    """

    _this_identifier: Bytes
    _k_buckets: KBuckets
    _ping_queue: List[Tuple[Float, Connection]]
    _stored_keys: List[Bytes]
    _node_lookup_requests: Dict[Bytes, NodeLookupRequest]

    def __init__(self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket) -> None:
        super().__init__(stack, node_info, Layer3Protocol, socket, isolated_logger(LoggerHandlers.LAYER_3))

        # Store this node's identifier.
        self._this_identifier = self._stack._layer4._this_identifier

        # Initialize the DHT-oriented attributes.
        self._k_buckets = [[] for _ in range(8 * DHT_KEY_LENGTH)]
        self._ping_queue = []
        self._stored_keys = []
        self._node_lookup_requests = {}

        # Start listening on the socket for this layer.
        self._logger.debug("Layer 3 Ready")

    def join_distributed_hash_table_network(self, known_node: Connection) -> None:
        self._logger.debug(f"Joining DHT network with known node {known_node}")

        # Calculate the distance between this node and the known node. Store the node in the appropriate k-bucket.
        distance = node_distance(self._this_identifier, known_node.that_identifier)
        k_bucket_index = math.floor(math.log2(distance))
        self._k_buckets[k_bucket_index].append(known_node)

        # Lookup this node, as this contacts the known node and other nodes, joining this node to the network.
        self._node_lookup(self._this_identifier)

        # todo: after lookup is done, host the stored keys
        # for file_identifier in glob.glob(DHT_STORE_PATH % "*"):
        #     file_name = os.path.basename(file_identifier)
        #     file_name = os.path.split(file_name)[0]
        #     self._stored_keys.append(file_name)

    def get_resource(self, key: Bytes) -> Bool:
        # Hash the key to get the resource key, and lookup the node closest to the resource key.
        resource_key = Hasher.hash(key, HashAlgorithm.SHA3_256())
        self._node_lookup(resource_key, find_value=True)

        # Wait for the resource key to be stored, and return True if it is.
        while resource_key not in self._stored_keys: pass
        return True  # todo: when to return False?

    def put_resource(self, key: Bytes, value: Bytes) -> None:
        # Hash the key to get the resource key, and find the k closest nodes to the resource key.
        resource_key = Hasher.hash(key, HashAlgorithm.SHA3_256())
        closest_k = sorted(self._all_known_nodes, key=lambda n: node_distance(n.identifier, resource_key))[:DHT_K_VALUE]

        # Send the resource to the k closest nodes.
        for node in closest_k:
            request = PutResourceRequest(resource_key=resource_key, resource_value=value)
            self._send_secure(node, request)

    def _node_lookup(self, target_node_identifier: Bytes, find_value: Bool = False) -> None:
        # Get this node's closest "alpha" nodes, and initiate a node lookup request.
        closest_alpha_nodes = self._all_known_nodes[:DHT_ALPHA]
        lookup_request = NodeLookupRequest(target_node_identifier=target_node_identifier, current_closest=None)
        self._node_lookup_requests[target_node_identifier] = lookup_request

        # Send a find node request to the closest alpha nodes.
        for closest_alpha_node in closest_alpha_nodes:
            request = FindNodeRequest(target_identifier=target_node_identifier)
            self._send_secure(closest_alpha_node, request)

    def _recursive_search(self, node_identifier: Bytes, node_address: Tuple[Str, Int], target_identifier: Bytes) -> None:
        # Connect to the node, and update the k-buckets.
        connection = self._stack._layer4.connect(node_address, node_identifier)

        # Send a get resource request to the node.
        connection = self._stack._layer4.connect(node_address, node_identifier)
        request = FindNodeRequest(target_identifier=target_identifier)
        self._send_secure(connection, request)

    def _update_k_buckets(self, node: Connection) -> None:
        # Determine the distance between this node and the new node.
        distance = node_distance(self._this_identifier, node.that_identifier)
        if distance == 0: return

        # Determine the k-bucket for the new node.
        k_bucket = self._k_buckets[math.floor(math.log2(distance))]

        # If the node is already in the k-bucket, move it to the tail.
        k_bucket_node_ids = [n.identifier for n in k_bucket]
        if node.that_identifier in k_bucket_node_ids:
            node_index = k_bucket_node_ids.index(node.that_identifier)
            k_bucket.append(k_bucket.pop(node_index))

        # Otherwise, if the k-bucket is not full, add the node to the tail.
        elif len(k_bucket) < DHT_K_VALUE:
            k_bucket.append(node)

        # Otherwise, if the k-bucket is full, ping the head node.
        else:
            # Get the head node, and send a ping request.
            head_node = k_bucket[0]
            current_time = time.time()
            request = PingRequest(ping_timestamp=current_time)

            # Add the ping request to the ping queue, and send the ping request.
            self._ping_queue.append((current_time, head_node))
            self._send_secure(head_node, request)

            # Wait for the ping response, or until the timeout. Todo: timestamping
            while (current_time, head_node) in self._ping_queue and time.time() - current_time < 5:
                pass

            # If the ping response was not received, remove the head node from the k-bucket.
            if (current_time, head_node) in self._ping_queue:
                k_bucket.remove(head_node)
                self._ping_queue.remove((current_time, head_node))

            # Otherwise, move the head node to the tail, and discard the new node.
            else:
                k_bucket.remove(head_node)
                k_bucket.append(head_node)

    def _closest_k_nodes_to(self, target_identifier: Bytes) -> KBucket:
        node_distances = [(c, node_distance(c.that_identifier, target_identifier)) for c in self._all_known_nodes]
        node_distances.sort(key=operator.itemgetter(1))
        closest_nodes = [c for c, _ in node_distances[:DHT_K_VALUE]]
        return closest_nodes

    @strict_isolation
    def _handle_command(self, address: IPv6Address, port: Int, data: Json) -> None:
        # Deserialize the request and call the appropriate handler.
        request_type = globals()[Layer3Protocol(data["protocol"]).name]
        request = request_type.deserialize(data)
        token = request.connection_token

        # Match the command to the appropriate handler.
        match request.protocol:

            # Handle a ping request.
            case Layer3Protocol.PingRequest.value:
                thread = Thread(target=self._handle_ping_request, args=(address, port, request))
                thread.start()

            # Handle a pong response.
            case Layer3Protocol.PongResponse.value:
                thread = Thread(target=self._handle_pong_response, args=(request,))
                thread.start()

            # Handle a put resource request.
            case Layer3Protocol.PutResourceRequest.value:
                thread = Thread(target=self._handle_put_resource_request, args=(request,))
                thread.start()

            # Handle a get resource request.
            case Layer3Protocol.GetResourceRequest.value:
                thread = Thread(target=self._handle_get_resource_request, args=(request,))
                thread.start()

            # Handle a return resource response.
            case Layer3Protocol.ReturnResourcePassResponse.value:
                thread = Thread(target=self._handle_return_resource_pass_response, args=(request,))
                thread.start()

            # Handle a find node request.
            case Layer3Protocol.FindNodeRequest.value:
                thread = Thread(target=self._handle_find_node_request, args=(request,))
                thread.start()

            # Handle a find node response.
            case Layer3Protocol.FindNodeResponse.value:
                thread = Thread(target=self._handle_find_node_response, args=(request,))
                thread.start()

            # Handle either an invalid command from a connected token, or an invalid command/state combination.
            case _:
                self._logger.warning(f"Received invalid command from token {token}.")

    def _handle_ping_request(self, request: PingRequest) -> None:
        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[request.connection_token]

        # Respond with a pong response, containing the request timestamp.
        self._send_secure(connection, PongResponse(ping_timestamp=request.ping_timestamp))

    def _handle_pong_response(self, address: IPv6Address, request: PongResponse) -> None:
        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[request.connection_token]
        timestamp = request.ping_timestamp

        # Remove the ping request from the ping queue.
        if (timestamp, connection) in self._ping_queue:
            self._ping_queue.remove((timestamp, connection))
            return

        # If a "pong" is received either from a non-pinged node, or after the timeout, log a warning.
        self._logger.warning(f"Received unexpected pong response from {connection.that_identifier}.")

    def _handle_put_resource_request(self, request: PutResourceRequest) -> None:
        # Store the key and value in the DHT.
        self._stored_keys.append(request.resource_key)
        with SafeFileOpen(DHT_STORE_PATH % request.resource_key.hex(), "wb") as fo:
            fo.write(request.resource_value)

    def _handle_get_resource_request(self, request: GetResourceRequest) -> None:
        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[request.connection_token]
        resource_key = request.resource_key

        # Check if this node is hosting the requested key.
        if resource_key in self._stored_keys:
            with SafeFileOpen(DHT_STORE_PATH % resource_key.hex(), "rb") as fo:
                resource_value = fo.read()
            response = ReturnResourcePassResponse(resource_key=resource_key, resource_value=resource_value)
            self._send_secure(connection, response)

        # Otherwise, find the closest known nodes to the key.
        else:
            closest_nodes = self._closest_k_nodes_to(resource_key)
            closest_node_identifiers = [n.that_identifier for n in closest_nodes]
            closest_node_addresses = [(n.that_address.exploded, n.that_port) for n in closest_nodes]

            response = ReturnResourceFailResponse(
                resource_key=resource_key,
                closest_node_identifiers=closest_node_identifiers,
                closest_node_addresses=closest_node_addresses)
            self._send_secure(connection, response)

    def _handle_return_resource_pass_response(self, request: ReturnResourcePassResponse) -> None:
        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[request.connection_token]
        resource_key = request.resource_key

        # Store the key and value in the DHT.
        self._stored_keys.append(resource_key)
        with SafeFileOpen(DHT_STORE_PATH % resource_key.hex(), "wb") as fo:
            fo.write(request.resource_value)

    def _handle_return_resource_fail_response(self, request: ReturnResourceFailResponse) -> None:
        # Otherwise, try to request the resource from the closest nodes.
        for node_identifier, node_address in zip(request.closest_node_identifiers, request.closest_node_addresses):
            thread = Thread(target=self._recursive_search, args=(node_identifier, node_address, request.resource_key))
            thread.start()

    def _handle_find_node_request(self, address: IPv6Address, request: FindNodeRequest) -> None:
        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[request.connection_token]

        # Get the k closest nodes to the target identifier.
        closest_nodes = self._closest_k_nodes_to(request.target_identifier)
        closest_node_identifiers = [n.that_identifier for n in closest_nodes]
        closest_node_addresses = [(n.that_address.exploded, n.that_port) for n in closest_nodes]

        response = FindNodeResponse(
            target_identifier=request.target_identifier,
            closest_nodes_identifiers=closest_node_identifiers,
            closest_nodes_addresses=closest_node_addresses)
        self._send_secure(connection, response)

    def _handle_find_node_response(self, address: IPv6Address, request: FindNodeResponse) -> None:
        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[request.connection_token]
        target_identifier = request.target_identifier
        node_lookup_request = self._node_lookup_requests[target_identifier]

        # Mark the node as queried.
        with node_lookup_request.lock:
            if connection not in node_lookup_request.queried_nodes:
                node_lookup_request.queried_nodes.append(connection)

        # If all the closest nodes returned have already been queried, return.
        new_node_identifiers = request.closest_nodes_identifiers
        new_node_addresses = request.closest_nodes_addresses
        for new_node_identifier, new_node_address in zip(new_node_identifiers.copy(), new_node_addresses.copy()):
            if new_node_identifier in self._all_known_nodes:
                new_node_identifiers.remove(new_node_identifier)
                new_node_addresses.remove(new_node_address)
        if not new_node_identifiers:
            return

        # Select a sample of the nodes to query.
        new_nodes = [(n, m) for n, m in zip(new_node_identifiers, new_node_addresses)]
        alpha_selection = random.sample(new_nodes, DHT_ALPHA)
        for alpha_node in alpha_selection:
            Thread(target=self._recursive_search, args=(*alpha_node, target_identifier)).start()

        # If all the nodes are further away than the current closest, query all other k nodes.
        if all(map(lambda n: node_distance(n[0], target_identifier) > node_lookup_request.closest_distance, new_nodes)):
            for new_node in new_nodes:
                Thread(target=self._recursive_search, args=(*new_node, target_identifier)).start()

    @property
    def _all_known_nodes(self) -> KBucket:
        return sum(self._k_buckets, [])
