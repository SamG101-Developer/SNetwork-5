import random
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from threading import Lock, Thread
import glob, json, logging, lzma, operator, os.path, math, time

from src.CommStack2.LayerN import LayerN, LayerNProtocol, Connection
from src.CommStack2.Layer4 import Layer4, Layer4Protocol
from src.Crypt.Symmetric import SymmetricEncryption
from src.Crypt.Hash import Hasher, SHA3_256
from src.Utils.Types import Bool, Dict, Int, Json, Bytes, List, Optional, Tuple, Float
from src.CONFIG import DHT_STORE_PATH, DHT_ALPHA, DHT_K_VALUE, DHT_KEY_LENGTH, LAYER_3_PORT, DEFAULT_IPV6


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
        _recursive_search: Recursively searches for a resource in the DHT.
        _update_k_buckets: Updates the k-buckets with a new node.
        _closest_k_nodes_to: Returns the k closest nodes to a target identifier.
        _handle_ping: Handles a ping request.
        _handle_pong: Handles a pong response.
        _handle_put_resource: Handles a put resource request.
        _handle_get_resource: Handles a get resource request.
        _handle_return_resource: Handles a return resource response.
        _handle_find_node: Handles a find node request.
        _handle_find_node_response: Handles a find node response.
        _all_known_nodes: Returns all known nodes in the DHT (flattens k_buckets).
    """

    _level4: Layer4
    _this_identifier: Bytes
    _k_buckets: KBuckets
    _ping_queue: List[Tuple[Float, Connection]]
    _stored_keys: List[Bytes]
    _node_lookup_requests: Dict[Bytes, NodeLookupRequest]

    def __init__(self, layer4: Layer4) -> None:
        super().__init__()

        # Store the Layer 4 instance and this node's identifier.
        self._level4 = layer4
        self._this_identifier = self._level4._this_identifier

        # Initialize the DHT-oriented attributes.
        self._k_buckets = [[] for _ in range(8 * DHT_KEY_LENGTH)]
        self._ping_queue = []
        self._stored_keys = []
        self._node_lookup_requests = {}

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
        # Check the connection is in the accepted state.
        if connection.state != Layer4Protocol.AcceptConnection:
            logging.error(f"Cannot send data to connection in state {connection.state}.")
            return

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

        # todo: after lookup is done, host the stored keys
        # for file_identifier in glob.glob(DHT_STORE_PATH % "*"):
        #     file_name = os.path.basename(file_identifier)
        #     file_name = os.path.split(file_name)[0]
        #     self._stored_keys.append(file_name)

    def get_resource(self, key: Bytes) -> Bool:
        # Hash the key to get the resource key, and lookup the node closest to the resource key.
        resource_key = Hasher.hash(key, SHA3_256())
        self._node_lookup(resource_key, find_value=True)

        # Wait for the resource key to be stored, and return True if it is.
        while resource_key not in self._stored_keys: pass
        return True  # todo: when to return False?

    def put_resource(self, key: Bytes, value: Bytes) -> None:
        # Hash the key to get the resource key, and find the k closest nodes to the resource key.
        resource_key = Hasher.hash(key, SHA3_256())
        closest_k = sorted(self._all_known_nodes, key=lambda n: node_distance(n.identifier, resource_key))[:DHT_K_VALUE]

        # Send the resource to the k closest nodes.
        for node in closest_k:
            request = {
                "command": Layer3Protocol.PutResource.value,
                "key": key,
                "value": value}
            self._send(node, request)

    def _node_lookup(self, target_node_identifier: Bytes, find_value: Bool = False) -> None:
        # Get this node's closest "alpha" nodes, and initiate a node lookup request.
        closest_alpha_nodes = self._all_known_nodes[:DHT_ALPHA]
        lookup_request = NodeLookupRequest(target_node_identifier=target_node_identifier, current_closest=None)
        self._node_lookup_requests[target_node_identifier] = lookup_request

        # Send a find node request to the closest alpha nodes.
        for closest_alpha_node in closest_alpha_nodes:
            request = {
                "command": Layer3Protocol.FindNode.value if not find_value else Layer3Protocol.GetResource.value,
                "target_node_identifier": target_node_identifier}
            Thread(target=self._send, args=(closest_alpha_node, request)).start()

    def _recursive_search(self, node: Json, target_identifier: Bytes) -> None:
        # Get the address and identifier of the node.
        node_address = IPv6Address(bytes.fromhex(node["address"]))
        node_identifier = bytes.fromhex(node["identifier"])

        # Select a random connection to the node if any exist. Otherwise, create a new connection.
        connection_candidates = [c for c in self._level4._conversations.values() if c.identifier == node_identifier]
        connection = random.choice(connection_candidates) if connection_candidates else self._level4.connect(node_address, node_identifier)

        # Send a get resource request to the node.
        connection = self._level4.connect(node_address, node_identifier)
        request = {
            "command": Layer3Protocol.GetResource.value,
            "target": target_identifier}
        self._send(connection, request)

    def _update_k_buckets(self, node: Connection) -> None:
        # Determine the distance between this node and the new node.
        distance = node_distance(self._this_identifier, node.identifier)
        if distance == 0: return

        # Determine the k-bucket for the new node.
        k_bucket = self._k_buckets[math.floor(math.log2(distance))]

        # If the node is already in the k-bucket, move it to the tail.
        k_bucket_node_ids = [n.identifier for n in k_bucket]
        if node.identifier in k_bucket_node_ids:
            node_index = k_bucket_node_ids.index(node.identifier)
            k_bucket.append(k_bucket.pop(node_index))

        # Otherwise, if the k-bucket is not full, add the node to the tail.
        elif len(k_bucket) < DHT_K_VALUE:
            k_bucket.append(node)

        # Otherwise, if the k-bucket is full, ping the head node.
        else:
            # Get the head node, and send a ping request.
            head_node = k_bucket[0]
            current_time = time.time()
            request = {
                "command": Layer3Protocol.Ping.value,
                "timestamp": current_time}

            # Add the ping request to the ping queue, and send the ping request.
            self._ping_queue.append((current_time, head_node))
            self._send(head_node, request)

            # Wait for the ping response, or until the timeout.
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
        node_distances = [(c, node_distance(c.identifier, target_identifier)) for c in self._all_known_nodes]
        node_distances.sort(key=operator.itemgetter(1))
        closest_nodes = [{"address": c.address.packed.hex(), "identifier": c.identifier.hex()} for c, _ in node_distances[:DHT_K_VALUE]]
        return closest_nodes

    def _handle_ping(self, address: IPv6Address, request: Json) -> None:
        # Get the token and connection.
        token = bytes.fromhex(request["token"])
        connection = self._level4._conversations[token]

        # Send a pong response.
        response = {
            "command": Layer3Protocol.Pong.value,
            "timestamp": request["timestamp"]}
        self._send(connection, response)

    def _handle_pong(self, address: IPv6Address, request: Json) -> None:
        # Get the token and connection.
        token = bytes.fromhex(request["token"])
        connection = self._level4._conversations[token]
        timestamp = request["timestamp"]

        # Remove the ping request from the ping queue.
        if (timestamp, connection) in self._ping_queue:
            self._ping_queue.remove((timestamp, connection))
            return

        # If a "pong" is received either from a non-pinged node, or after the timeout, log a warning.
        logging.warning(f"Received unexpected pong response from {connection.address}.")

    def _handle_put_resource(self, address: IPv6Address, request: Json) -> None:
        # Get the key and value from the request.
        file_identifier = bytes.fromhex(request["key"])
        compressed_file_contents = bytes.fromhex(request["value"])
        decompressed_file_contents = lzma.decompress(compressed_file_contents)

        # Store the key and value in the DHT.
        self._stored_keys.append(file_identifier)
        open(DHT_STORE_PATH % file_identifier, "wb").write(decompressed_file_contents)

    def _handle_get_resource(self, address: IPv6Address, request: Json) -> None:
        # Get the token, connection and file identifier from the request.
        token = bytes.fromhex(request["token"])
        file_identifier = bytes.fromhex(request["target"])
        connection = self._level4._conversations[token]

        # Check if this node is hosting the requested key.
        if file_identifier in self._stored_keys:
            decompressed_file_contents = open(DHT_STORE_PATH % file_identifier, "rb").read()
            response = {
                "command": Layer3Protocol.ReturnResource.value,
                "found": True,
                "key": file_identifier,
                "value": lzma.compress(decompressed_file_contents)}

            self._send(connection, response)

        # Otherwise, find the closest known nodes to the key.
        else:
            response = {
                "command": Layer3Protocol.ReturnResource.value,
                "found": False,
                "closest_nodes": self._closest_k_nodes_to(file_identifier)}

            self._send(connection, response)

    def _handle_return_resource(self, address: IPv6Address, request: Json) -> None:
        # Get the token, connection, the file identifier from the request.
        token = bytes.fromhex(request["token"])
        file_identifier = bytes.fromhex(request["key"])
        connection = self._level4._conversations[token]

        # If the resource was found, store the key and value in the DHT.
        if request["found"]:
            compressed_file_contents = bytes.fromhex(request["value"])
            decompressed_file_contents = lzma.decompress(compressed_file_contents)
            self._stored_keys.append(file_identifier)
            open(DHT_STORE_PATH % file_identifier, "wb").write(decompressed_file_contents)

        # Otherwise, try to request the resource from the closest nodes.
        else:
            for node in request["closest_nodes"]:
                Thread(target=self._recursive_search, args=(node, file_identifier)).start()

    def _handle_find_node(self, address: IPv6Address, request: Json) -> None:
        target_identifier = bytes.fromhex(request["target_node_identifier"])
        response = {
            "command": Layer3Protocol.FindNodeResponse.value,
            "closest_nodes": self._closest_k_nodes_to(target_identifier),
        }

    def _handle_find_node_response(self, address: IPv6Address, request: Json) -> None:
        token = bytes.fromhex(request["token"])
        target_identifier = bytes.fromhex(request["target_node_identifier"])

        connection = self._level4._conversations[token]
        node_lookup_request = self._node_lookup_requests[target_identifier]

        # Mark the node as queried.
        with node_lookup_request.lock:
            if connection not in node_lookup_request.queried_nodes:
                node_lookup_request.queried_nodes.append(connection)

        # If all the closest nodes returned have already been queried, return.
        new_nodes = request["closest_nodes"]
        new_nodes = [n for n in new_nodes if bytes.fromhex(n["identifier"]) not in [n.identifier for n in self._all_known_nodes]]
        if not new_nodes:
            return

        # Select a sample of the nodes to query.
        alpha_selection = random.sample(new_nodes, DHT_ALPHA)
        for alpha_node in alpha_selection:
            Thread(target=self._recursive_search, args=(alpha_node, target_identifier)).start()

        # If all the nodes are further away than the current closest, query all other k nodes.
        if all(map(lambda n: node_distance(bytes.fromhex(n["identifier"]), target_identifier) > node_lookup_request.closest_distance, new_nodes)):
            for new_node in new_nodes:
                Thread(target=self._recursive_search, args=(new_node, target_identifier)).start()

    @property
    def _all_known_nodes(self) -> KBucket:
        return sum(self._k_buckets, [])
