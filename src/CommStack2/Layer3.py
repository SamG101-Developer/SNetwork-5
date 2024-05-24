from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from threading import Lock, Thread
import json, logging, math

from src.CommStack2.LayerN import LayerN, LayerNProtocol, Connection
from src.CommStack2.Layer4 import Layer4, Layer4Protocol
from src.Crypt.Symmetric import SymmetricEncryption
from src.Crypt.Hash import Hasher, SHA3_256
from src.Utils.Types import Bool, Int, Json, Bytes, List, Optional
from src.CONFIG import DHT_ALPHA, DHT_K_VALUE, DHT_KEY_LENGTH, LAYER_3_PORT, DEFAULT_IPV6


type KBucket = List[Connection]
type KBuckets = List[KBucket]


def node_distance(a: Bytes, b: Bytes) -> Int:
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


@dataclass(kw_only=True)
class NodeLookupRequest:
    target_node_identifier: Bytes
    current_closest: Connection
    lock: Lock = field(init=False, default_factory=Lock)
    queried_nodes: List[Connection] = field(init=False, default_factory=list)

    @property
    def closest_distance(self) -> Int:
        return node_distance(self.target_node_identifier, self.current_closest.identifier)


class Layer3Protocol(LayerNProtocol, Enum):
    Ping = 0
    Pong = 1
    PutResource = 2
    GetResource = 3
    ReturnResource = 4
    FindNode = 5
    FindNodeResponse = 6


class Layer3(LayerN):
    """
    Layer 3 of the Communication Stack is the "Distributed Layer". This layer is responsible for traversing the DHT and
    finding the closest nodes to a target node. It is also responsible for storing and retrieving resources from the
    DHT.

    Data sent in this layer authenticated-encrypted, as the connections must be established securely from Layer 4,
    before any data is sent.

    Attributes:
        _level4: The Layer 4 instance.
        _this_identifier: The identifier of this node.
        _k_buckets: The list of k-buckets, each containing a list of connections.
        _ping_queue: The list of connections that have been pinged.
        _stored_keys: The list of keys stored in the DHT.
        _node_lookup_requests: The list of node lookup requests.

    Methods:
        join_distributed_hash_table_network: Joins the DHT network.
        get_resource: Retrieves a resource from the DHT.
        put_resource: Stores a resource in the DHT.
        _listen: Listens for incoming raw requests and handles them in a new thread.
        _handle_command: Handles a command received from a remote node.
        _send: Sends data to a remote node.
        _node_lookup: Initiates a node lookup request.
        _update_k_buckets: Updates the k-buckets with a new node.
        _handle_ping: Handles a ping request.
        _handle_pong: Handles a pong response.
        _handle_put_resource: Handles a put resource request.
        _handle_get_resource: Handles a get resource request.
        _handle_return_resource: Handles a return resource response.
        _handle_find_node: Handles a find node request.
        _handle_find_node_response: Handles a find node response.
    """

    _level4: Layer4
    _this_identifier: Bytes
    _k_buckets: KBuckets
    _ping_queue: List[Connection]
    _stored_keys: List[Bytes]
    _node_lookup_requests: List[NodeLookupRequest]

    def __init__(self, layer4: Layer4) -> None:
        super().__init__()

        # Store the Layer 4 instance and this node's identifier.
        self._level4 = layer4
        self._this_identifier = self._level4._this_identifier

        # Initialize the DHT-oriented attributes.
        self._k_buckets = [[] for _ in range(8 * DHT_KEY_LENGTH)]
        self._ping_queue = []
        self._stored_keys = []
        self._node_lookup_requests = []

        # Start listening on both sockets.
        Thread(target=self._listen).start()
        logging.debug("Layer 3 Ready")

    def _listen(self) -> None:
        # Bind the insecure socket to port 40000.
        self._socket.bind((DEFAULT_IPV6, self._port))

        # Listen for incoming raw requests, and handle them in a new thread.
        while True:
            data, address = self._socket.recvfrom(4096)
            request = json.loads(data)
            token, encrypted_data = request["token"], request["data"]

            if token in self._level4._conversations.keys() and self._level4._conversations[token].state == Layer4Protocol.AcceptConnection:
                e2e_key = self._level4._conversations[token].e2e_primary_key
                decrypted_data = SymmetricEncryption.decrypt(e2e_key, encrypted_data)
                decrypted_json = json.loads(decrypted_data)
                Thread(target=self._handle_command, args=(IPv6Address(address[0]), decrypted_json)).start()

            else:
                logging.warning(f"Received request from unknown token {token}.")
                continue

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        # Check the request has a command and token.
        if "command" not in request or "token" not in request:
            logging.error(f"Invalid request: {request}")
            return

        # Match the command to the appropriate handler.
        match request["command"]:
            case Layer3Protocol.Ping.value:
                self._handle_ping(address, request)
            case Layer3Protocol.Pong.value:
                self._handle_pong(address, request)
            case Layer3Protocol.PutResource.value:
                self._handle_put_resource(address, request)
            case Layer3Protocol.GetResource.value:
                self._handle_get_resource(address, request)
            case Layer3Protocol.ReturnResource.value:
                self._handle_return_resource(address, request)
            case Layer3Protocol.FindNode.value:
                self._handle_find_node(address, request)
            case Layer3Protocol.FindNodeResponse.value:
                self._handle_find_node_response(address, request)
            case _:
                logging.error(f"Invalid command: {request["command"]}")

    def _send(self, connection: Connection, data: Json) -> None:
        # Encrypt the data with the end-to-end key.
        e2e_key = self._level4._conversations[connection.token].e2e_primary_key
        encrypted_data = SymmetricEncryption.encrypt(e2e_key, json.dumps(data).encode())
        wrapped = {"token": connection.token, "data": encrypted_data}

        # Send the encrypted data to the address.
        encoded_data = json.dumps(wrapped).encode()
        self._socket.sendto(encoded_data, (connection.address.exploded, self._port))

    @property
    def _port(self) -> Int:
        # Get the port from the configuration.
        return LAYER_3_PORT

    def join_distributed_hash_table_network(self, known_node: Connection) -> None:
        logging.debug(f"Joining DHT network with known node {known_node}")

        # Calculate the distance between this node and the known node. Store the node in the appropriate k-bucket.
        distance = node_distance(self._this_identifier, known_node.identifier)
        k_bucket_index = math.floor(math.log2(distance))
        self._k_buckets[k_bucket_index].append(known_node)

        # Lookup this node, as this contacts the known node and other nodes, joining this node to the network.
        self._node_lookup(self._this_identifier)

    def get_resource(self, key: Bytes) -> Bool:
        # Hash the key to get the resource key, and lookup the node closest to the resource key.
        resource_key = Hasher.hash(key, SHA3_256())
        self._node_lookup(resource_key, find_value=True)

        # Wait for the resource key to be stored, and return True if it is.
        while resource_key not in self._stored_keys: pass
        return True  # todo: when to return False?

    def put_resource(self, key: Bytes, value: Bytes) -> None:
        resource_key = Hasher.hash(key, SHA3_256())

    def _node_lookup(self, target_node_identifier: Bytes, find_value: Bool = False) -> None:
        ...

    def _update_k_buckets(self, node: Connection) -> None:
        ...

    def _handle_ping(self, address: IPv6Address, request: Json) -> None:
        ...

    def _handle_pong(self, address: IPv6Address, request: Json) -> None:
        ...

    def _handle_put_resource(self, address: IPv6Address, request: Json) -> None:
        ...

    def _handle_get_resource(self, address: IPv6Address, request: Json) -> None:
        ...

    def _handle_return_resource(self, address: IPv6Address, request: Json) -> None:
        ...

    def _handle_find_node(self, address: IPv6Address, request: Json) -> None:
        ...

    def _handle_find_node_response(self, address: IPv6Address, request: Json) -> None:
        ...
