"""
The Node class sends commands to other nodes, over an encrypted connection. The connection is setup by the class,
isolating the layers of the communication stack. The Node class is responsible for sending and receiving messages from
other nodes, and is the primary interface for the application to communicate with other nodes.

The secure socket uses ephemeral keys, signed by static keys, to KEM-wrap a master key. This master key is then used for
authenticated symmetric encryption. This enables perfect forward secrecy, as the master key is only used for the
duration of the connection, and the ephemeral keys are discarded after the connection is closed. No two master keys are
wrapped by the same ephemeral public key. Multiple keys might be derived from the same master key.

The encrypted connection has a slightly different protocol, as the secure socket needs the connection token to be
prepended to the ciphertext, to know which key needs to be used to attempt decryption. The connection token is also
embedded into the encrypted request, so even if the prepended connection token is tampered with, the later comparison
will fail, and the connection will be closed.
"""


from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address
from threading import Thread
import logging, json, os

from src.CommStack.Level1 import Level1, Level1Protocol
from src.CommStack.LevelN import LevelN, LevelNProtocol, Connection
from src.Crypt.AsymmetricKeys import PubKey, SecKey
from src.Crypt.KEM import KEM
from src.Crypt.Sign import Signer
from src.Crypt.Symmetric import SymmetricEncryption
from src.Utils.Types import Bytes, Dict, Int, Json, List, Optional
from src.CONFIG import LEVEL_2_PORT


class Level2Protocol(LevelNProtocol, Enum):
    ExtendRoute = 0
    ExtendRouteAccept = 1
    ExtendRouteReject = 2
    GetEphemeralPubKeyForKEM = 3
    KEMWrappedMasterKey = 4
    SignHashMasterKey = 5
    Forward = 6
    GetRandomNodes = 7
    RandomNodes = 8


class Level2State(Enum):
    Waiting = 0
    Accepted = 1
    Rejected = 2


@dataclass
class RouteNode:
    address: IPv4Address
    identifier: Bytes
    public_key: Optional[Bytes]
    e2e_master_key: Optional[Bytes]
    state: Level2State = field(default=Level2State.Waiting, init=False)


@dataclass
class Route:
    token: Bytes
    nodes: List[RouteNode]
    entry_token: Optional[Bytes] = field(default=None, init=False)


@dataclass
class TunnelKeyGroup:
    ephemeral_secret_key: Bytes
    e2e_master_key: Optional[Bytes]


class Level2(LevelN):
    _level1: Level1

    _route: Optional[Route]
    _route_forward_token_map: Dict[Bytes, Bytes]
    _route_backward_token_map: Dict[Bytes, Bytes]
    _tunnel_keys: Dict[Bytes, TunnelKeyGroup]
    _temp_random_nodes: List[Int]

    def __init__(self, level1: Level1):
        super().__init__()

        self._level1 = level1
        self._route = None

        self._route_forward_token_map = {}
        self._route_backward_token_map = {}
        self._tunnel_keys = {}
        self._temp_random_nodes = []

        Thread(target=self._listen).start()

        logging.debug("Layer 2 Ready")

    def _listen(self) -> None:
        # Bind the secure socket to port 40001.
        self._socket.bind(("", self._port))

        # Listen for incoming encrypted requests, and handle them in a new thread.
        while True:
            data, address = self._socket.recvfrom(4096)

            # Split the connection token from the ciphertext, and ensure a connection with this token exists.
            token, encrypted_data = data[:32], data[32:]
            connection = self._level1._conversations.get(token)
            if not connection or not connection.e2e_master_key:
                continue

            # Decrypt the ciphertext with the key corresponding to the connection token.
            decrypted_data = SymmetricEncryption.decrypt(encrypted_data, connection.e2e_master_key)
            request = json.loads(decrypted_data)

            # Ensure that the connection token received matches the connection token embedded in the request.
            if request["token"] != token.hex():
                continue

            # Handle the command in a new thread.
            Thread(target=self._handle_command, args=(IPv4Address(address[0]), request)).start()

    def _handle_command(self, address: IPv4Address, request: Json) -> None:
        # Check that the request has a command and token, and parse the token.
        if "command" not in request or "token" not in request:
            return
        token = bytes.fromhex(request["token"])

        match request["command"]:
            case Level2Protocol.ExtendRoute.value:
                self._handle_extend_route(address, token, request)
            case Level2Protocol.ExtendRouteAccept.value:
                self._handle_extend_route_accept(address, token, request)
            case Level2Protocol.ExtendRouteReject.value:
                self._handle_extend_route_reject(address, token, request)
            case Level2Protocol.GetEphemeralPubKeyForKEM.value:
                self._handle_get_ephemeral_pub_key_for_kem(address, token, request)
            case Level2Protocol.KEMWrappedMasterKey.value:
                self._handle_kem_wrapped_master_key(address, token, request)
            case Level2Protocol.RandomNodes.value:
                self._temp_random_nodes = request["nodes"].copy()

    def _send(self, connection: Connection, data: Json) -> None:
        # Check the connection is valid.
        if connection.state != Level1Protocol.AcceptConnection or not connection.e2e_master_key:
            return

        # Encrypt and send the request.
        raw_data = json.dumps(data).encode()
        encrypted_data = connection.token + SymmetricEncryption.encrypt(raw_data, connection.e2e_master_key)
        self._socket.sendto(encrypted_data, (connection.address.exploded, self._port))

    @property
    def _port(self) -> Int:
        return LEVEL_2_PORT

    def create_route(self) -> None:
        logging.debug("Creating a new route.")

        # Create a new route.
        self._route = Route(token=os.urandom(32), nodes=[])

        request = {
            "command": Level2Protocol.GetRandomNodes.value,
            "blocklist": [self._level1._level0.node_key]
        }
        while not self._temp_random_nodes:
            pass
        temp_random_nodes = self._temp_random_nodes.copy()
        self._temp_random_nodes.clear()
        iterator = iter(temp_random_nodes)

        # Extend the route to 3 more nodes.
        while len(self._route.nodes) < 4:
            next_node = json.loads(self._level1._level0.get(f"{next(iterator)}.key"))
            next_node = RouteNode(address=IPv4Address(next_node["ip"]), identifier=bytes.fromhex(next_node["id"]), public_key=None, e2e_master_key=None)
            request = {
                "command": Level2Protocol.ExtendRoute.value,
                "token": self._route.token.hex(),
                "route_token": self._route.token.hex(),
                "next_node_addr": next_node.address.exploded,
                "next_node_id": next_node.identifier.hex()
            }

            logging.debug(f"Extending route to {next_node.address}.")

            # Tunnel the message to the current final node, to extend the route.
            if self._route.nodes:
                self._tunnel_message_forward(self._route.token, self._route.nodes[-1].identifier, request)
            else:
                entry_connection = self._level1.connect(next_node.address, next_node.identifier)
                request = {
                    "command": Level2Protocol.GetEphemeralPubKeyForKEM.value,
                    "token": entry_connection.token.hex(),
                    "route_token": request["route_token"]
                }
                self._route.entry_token = entry_connection.token
                self._send(entry_connection, request)

            self._route.nodes.append(next_node)

            # Loop until either the node is confirmed (encryption key set), or needs to be removed.
            while True:
                if self._route.nodes[-1].state == Level2State.Accepted:
                    break
                if self._route.nodes[-1].state == Level2State.Rejected:
                    self._route.nodes.pop()
                    break

    def _handle_extend_route(self, address: IPv4Address, token: Bytes, request: Json) -> None:
        logging.log(f"Extending route to {request['next_node_addr']}.")

        # Attempt a connection to the next node in the route.
        next_node_address = IPv4Address(request["next_node_addr"])
        next_node_identifier = bytes.fromhex(request["next_node_id"])
        connection = self._level1.connect(next_node_address, next_node_identifier)

        # If the connection is successful, request an ephemeral key pair from the new node.
        if connection:
            request = {
                "command": Level2Protocol.GetEphemeralPubKeyForKEM.value,
                "token": connection.token.hex(),
                "route_token": request["route_token"]
            }
            self._send(connection, request)

            # Map the tokens for route tunnelling.
            self._route_forward_token_map[token] = connection.token
            self._route_backward_token_map[connection.token] = token

        # Otherwise, tell the client, via the route, that the route extension has been rejected.
        else:
            response = {
                "command": Level2Protocol.ExtendRouteReject.value,
                "token": token.hex()
            }
            route_token = bytes.fromhex(request["route_token"])
            self._tunnel_message_backward(token, route_token, response)

    def _handle_extend_route_reject(self, address: IPv4Address, token: Bytes, request: Json) -> None:
        # Mark the pending node as rejected
        self._route.nodes[-1].state = Level2State.Rejected

    def _handle_get_ephemeral_pub_key_for_kem(self, address: IPv4Address, token: Bytes, request: Json) -> None:
        logging.debug("Received request for ephemeral public key.")

        # Create an ephemeral key pair, and sign the public key with the static private key.
        this_ephemeral_key_pair = KEM.generate_key_pair()
        signature = Signer.sign(self._level1._this_static_secret_key, this_ephemeral_key_pair.public_key.bytes)
        self._tunnel_keys[bytes.fromhex(request["route_token"])] = TunnelKeyGroup(ephemeral_secret_key=this_ephemeral_key_pair.secret_key.bytes, e2e_master_key=None)

        # Send the public key and signature to the previous node, who'll tunnel to the client.
        response = {
            "command": Level2Protocol.ExtendRouteAccept.value,
            "token": token.hex(),
            "ephemeral_pub_key": this_ephemeral_key_pair.public_key.bytes.hex(),
            "signature": signature.hex()
        }

        logging.debug(f"Sending ephemeral public key to {self._level1._conversations[token].address}.")
        self._send(self._level1._conversations[token], response)

    def _handle_extend_route_accept(self, address: IPv4Address, token: Bytes, request: Json) -> None:
        logging.debug("Received acceptance of route extension.")

        # Determine the identifier and static key of the new node.
        that_identifier = self._route.nodes[-1].identifier
        that_static_public_key = PubKey.from_bytes(bytes.fromhex(json.loads(self._level1._level0.get(f"{that_identifier.hex()}.key"))["pub_key"]))

        # Verify the signature, and add the ephemeral public key to the route.
        that_ephemeral_public_key = bytes.fromhex(request["ephemeral_pub_key"])
        that_ephemeral_public_key_signed = bytes.fromhex(request["signature"])

        if Signer.verify(that_static_public_key, that_ephemeral_public_key, that_ephemeral_public_key_signed):
            self._route.nodes[-1].public_key = that_ephemeral_public_key
            self._route.nodes[-1].e2e_master_key = os.urandom(32)
            self._route.nodes[-1].state = Level2State.Accepted
        else:
            self._route.nodes[-1].state = Level2State.Rejected
            return

        # KEM the master key, and tunnel the message to the node.
        kem_wrapped_master_key = KEM.kem_wrap(PubKey.from_bytes(that_ephemeral_public_key), self._route.nodes[-1].e2e_master_key).encapsulated
        response = {
            "command": Level2Protocol.KEMWrappedMasterKey.value,
            "token": token.hex(),
            "kem_wrapped_master_key": kem_wrapped_master_key.hex()}

    def _handle_kem_wrapped_master_key(self, address: IPv4Address, token: Bytes, request: Json) -> None:
        logging.debug("Received KEM-wrapped master key.")

        # Get the ephemeral public key for this route, and unwrap the master key.
        kem_wrapped_master_key = bytes.fromhex(request["kem_wrapped_master_key"])
        this_ephemeral_secret_key = self._tunnel_keys[bytes.fromhex(request["route_token"])].ephemeral_secret_key
        e2e_master_key = KEM.kem_unwrap(SecKey.from_bytes(this_ephemeral_secret_key), kem_wrapped_master_key).decapsulated

        # Save the master key, and sign a hash of it.
        self._tunnel_keys[bytes.fromhex(request["route_token"])].e2e_master_key = e2e_master_key
        signed_master_key = Signer.sign(self._level1._this_static_secret_key, e2e_master_key)

        # Tunnel the signed hashed master key back for authentication.
        response = {
            "command": Level2Protocol.SignHashMasterKey.value,
            "token": token.hex(),
            "signed_master_key": signed_master_key.hex()
        }
        route_token = bytes.fromhex(request["route_token"])
        self._tunnel_message_backward(token, route_token, response)

    def _handle_forward(self, address: IPv4Address, token: Bytes, request: Json) -> None:
        route_token = bytes.fromhex(request["route_token"])

        # From the previous node in the route.
        if token in self._route_forward_token_map.keys():
            logging.debug(f"Forwarding message forwards from {address} to {self._level1._conversations[self._route_forward_token_map[token]].address}.")

            next_layer = bytes.fromhex(request["message"])
            next_layer = json.loads(SymmetricEncryption.decrypt(self._tunnel_keys[route_token].e2e_master_key, next_layer))

            # Get the next connection to forward data too.
            next_token = self._route_forward_token_map[token]
            self._send(self._level1._conversations[next_token], next_layer)

        # From the next node in the route.
        elif token in self._route_backward_token_map:
            logging.debug(f"Forwarding message backwards from {address} to {self._level1._conversations[self._route_backward_token_map[token]].address}.")

            tunnel_key = self._tunnel_keys[route_token].e2e_master_key
            next_layer = {
                "command": Level2Protocol.Forward.value,
                "token": self._route_backward_token_map[token],
                "message": SymmetricEncryption.encrypt(tunnel_key, json.dumps(request).encode()).hex()
            }

            # Get the previous connection to forward data too.
            prev_token = self._route_backward_token_map[token]
            self._send(self._level1._conversations[prev_token], next_layer)

    def _tunnel_message_backward(self, token: Bytes, route_token: Bytes, message: Json) -> None:
        logging.debug(f"Tunnelling message backwards to client.")

        # To tunnel a message backward, add a layer of encryption and send the message backwards.
        # Reverse tunnelling starts at any route node and ends at the client node.
        tunnel_key = self._tunnel_keys[route_token].e2e_master_key
        message = {
            "command": Level2Protocol.Forward.value,
            "token": token,
            "message": SymmetricEncryption.encrypt(tunnel_key, json.dumps(message).encode()).hex()
        }

        # Send the message to the previous node in the route.
        connection = self._level1._conversations[token]
        self._send(connection, message)

    def _tunnel_message_forward(self, route_token: Bytes, target_node_id: Bytes, message: Json) -> None:
        logging.debug(f"Tunnelling message forwards to {target_node_id}.")

        # To tunnel a message forward, apply the levels of encryption upto and including the index of the target node.
        # Forward tunnelling starts at the client node and ends at any route node.

        # Find the index of the target node in the route.
        target_index = next(i for i, node in enumerate(self._route.nodes) if node.identifier == target_node_id)
        for i in range(target_index - 1, -1, -1):
            message = {
                "command": Level2Protocol.Forward.value,
                "token": self._route.entry_token,
                "message": SymmetricEncryption.encrypt(self._tunnel_keys[route_token].e2e_master_key, json.dumps(message).encode()).hex()
            }

        # Send the message to the entry node.
        connection = self._level1._conversations[self._route.nodes[0].identifier]
        self._send(connection, message)
