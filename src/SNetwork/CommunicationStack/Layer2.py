from __future__ import annotations

import logging
import lzma
import secrets
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket

from SNetwork.CommStack2.CommunicationStack import CommunicationStack
from SNetwork.CommStack2.LayerN import LayerN, LayerNProtocol, Connection
from SNetwork.Config import LAYER_2_PORT
from SNetwork.Crypt.AsymmetricKeys import PubKey, SecKey
from SNetwork.Crypt.KEM import KEM
from SNetwork.Crypt.Sign import Signer
from SNetwork.Crypt.Symmetric import SymmetricEncryption
from SNetwork.Utils.Types import Int, Json, Bytes, Dict, Optional, List
from SNetwork.Utils.Json import SafeJson


class RouteNodeState(Enum):
    Waiting = 0x00
    Accepted = 0x01
    Rejected = 0x02


@dataclass(kw_only=True)
class Route:
    route_token: Bytes
    entry_token: Bytes
    nodes: List[RouteNode]


@dataclass(kw_only=True)
class RouteNode:
    address: IPv6Address
    identifier: Bytes
    challenge: Bytes
    ephemeral_public_key: Optional[PubKey] = field(default=None)
    e2e_primary_key: Optional[Bytes] = field(default=None)
    state: RouteNodeState = field(default=RouteNodeState.Waiting)


@dataclass(kw_only=True)
class TunnelKeyGroup:
    ephemeral_secret_key: SecKey
    primary_key: Optional[Bytes] = field(default=None)


class Layer2Protocol(LayerNProtocol, Enum):
    ExtendConnection = 0x00
    TunnelRequest = 0x01
    TunnelEphemeralKey = 0x02
    TunnelPrimaryKey = 0x03
    TunnelAccept = 0x04
    TunnelReject = 0x05
    ForwardMessage = 0x06
    InternetSend = 0x07
    InternetRecv = 0x08


class Layer2(LayerN):
    _route: Optional[Route]
    _route_forward_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _route_reverse_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _tunnel_keys: Dict[Bytes, TunnelKeyGroup]     # Route ID => Tunnel Key Group

    def __init__(self, stack: CommunicationStack) -> None:
        super().__init__(stack)

    def _listen(self) -> None:
        pass

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        # Check the request has a command and token.
        if "command" not in request or "token" not in request:
            logging.error(f"Invalid request: {request}")
            return

        # Match the command to the appropriate handler.
        match request["command"]:
            case Layer2Protocol.ExtendConnection:
                self._handle_extend_connection(address, request)
            case Layer2Protocol.TunnelRequest:
                self._handle_tunnel_request(address, request)
            case Layer2Protocol.TunnelEphemeralKey:
                self._handle_tunnel_ephemeral_key(address, request)
            case Layer2Protocol.TunnelPrimaryKey:
                self._handle_tunnel_primary_key(address, request)
            case Layer2Protocol.TunnelAccept:
                self._handle_tunnel_accept(address, request)
            case Layer2Protocol.TunnelReject:
                self._handle_tunnel_reject(address, request)
            case Layer2Protocol.ForwardMessage:
                self._handle_forward_message(address, request)
            case Layer2Protocol.InternetSend:
                self._handle_internet_send(address, request)
            case Layer2Protocol.InternetRecv:
                self._handle_internet_recv(address, request)
            case _:
                logging.error(f"Invalid command: {request["command"]}")

    def _send(self, connection: Connection, data: Json) -> None:
        pass

    @property
    def _port(self) -> Int:
        return LAYER_2_PORT

    def create_route(self) -> None:
        ...

    def forward_internet_data(self, data: Bytes) -> None:
        request = {
            "command": Layer2Protocol.InternetSend.value,
            "data": lzma.compress(data).hex()}

        self._tunnel_message_forwards(request)

    def _handle_extend_connection(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Extending a connection to {address}")

        # Get the target address and identifier.
        target_address = IPv6Address(request["target_address"])
        target_identifier = bytes.fromhex(request["target_identifier"])
        route_token = bytes.fromhex(request["route_token"])

        # Connect to this target.
        extended_connection = self._stack._layer4.connect(target_address, target_identifier)

        # If the connection was successful, request an ephemeral public key from the target.
        if extended_connection:
            self._send(extended_connection, {
                "command": Layer2Protocol.TunnelRequest.value,
                "route_token": request["route_token"],
            })

        # Otherwise, the connection failed, so tunnel back to the target node.
        else:
            self._tunnel_message_backwards(route_token, {
                "command": Layer2Protocol.TunnelReject.value,
                "route_token": request["route_token"],
                "challenge": request["challenge"]
            })

    def _handle_tunnel_request(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received a tunnel request from {address}")

        # Get the tokens from the request.
        token = bytes.fromhex(request["route_token"])
        route_token = bytes.fromhex(request["route_token"])

        # Create an ephemeral public key.
        tunnel_ephemeral_public_key_pair = KEM.generate_key_pair()

        # Sign the challenge and ephemeral public key together and the challenge.
        challenge = bytes.fromhex(request["challenge"])
        signature = Signer.sign(
            my_static_secret_key=self._stack._layer4._this_static_secret_key,
            message=challenge + tunnel_ephemeral_public_key_pair.public_key.der,
            their_id=self._stack._layer4._conversations[token].identifier)
        self._tunnel_keys[route_token] = TunnelKeyGroup(ephemeral_secret_key=tunnel_ephemeral_public_key_pair.secret_key)

        # Send the ephemeral public key and signature back to the target's current final node.
        self._tunnel_message_backwards(route_token, {
            "command": Layer2Protocol.TunnelEphemeralKey.value,
            "ephemeral_public_key": tunnel_ephemeral_public_key_pair.public_key.der.hex(),
            "signature": signature.hex(),
        })

    def _handle_tunnel_ephemeral_key(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received a tunnel ephemeral key from {address}")

        # Determine crypto-related information regarding the target.
        target_ephemeral_public_key = PubKey.from_der(bytes.fromhex(request["ephemeral_public_key"]))
        target_signature = bytes.fromhex(request["signature"])
        target_certificate = self._stack._layer4._cached_certificates[self._route.nodes[-1].identifier]
        target_static_public_key = target_certificate.public_key

        # Verify the signature of the challenge and ephemeral public key.
        verification = Signer.verify(
            their_static_public_key=target_static_public_key,
            message=self._route.nodes[-1].challenge + target_ephemeral_public_key.der,
            signature=target_signature,
            target_id=self._route.nodes[-2].identifier)

        if not verification:
            logging.error(f"Invalid signature from {address}")
            self._route.nodes[-1].state = RouteNodeState.Rejected
            return

        # Save the target's ephemeral public key and generate a primary key.
        self._route.nodes[-1].ephemeral_public_key = target_ephemeral_public_key
        self._route.nodes[-1].e2e_primary_key = secrets.token_bytes(32)

        # Wrap the primary key with the target's ephemeral public key, and tunnel it forwards.
        wrapped_primary_key = KEM.kem_wrap(
            their_ephemeral_public_key=target_ephemeral_public_key,
            decapsulated_key=self._route.nodes[-1].e2e_primary_key).encapsulated

        self._tunnel_message_forwards({
            "command": Layer2Protocol.TunnelPrimaryKey.value,
            "route_token": self._route.route_token.hex(),
            "wrapped_primary_key": wrapped_primary_key.hex(),
        })

    def _handle_tunnel_primary_key(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received a tunnel primary key from {address}")

        # Get the route token.
        route_token = bytes.fromhex(request["route_token"])

        # Unwrap the primary key with the ephemeral public key, and save it.
        wrapped_primary_key = bytes.fromhex(request["wrapped_primary_key"])
        this_ephemeral_secret_key = self._tunnel_keys[route_token].ephemeral_secret_key
        primary_key = KEM.kem_unwrap(
            my_ephemeral_secret_key=this_ephemeral_secret_key,
            encapsulated_key=wrapped_primary_key).decapsulated

        self._tunnel_keys[route_token].primary_key = primary_key

        # Tunnel a signature of the hashed primary key back to the target for authentication.
        signed_primary_key = Signer.sign(
            my_static_secret_key=self._stack._layer4._this_static_secret_key,
            message=primary_key,
            their_id=self._stack._layer4._conversations[route_token].identifier)

        self._tunnel_message_backwards(route_token, {
            "command": Layer2Protocol.TunnelAccept.value,
            "route_token": route_token.hex(),
            "signed_primary_key": signed_primary_key.hex()})

    def _handle_tunnel_accept(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received a tunnel accept from {address}")

        # Get the primary key and the target node's signature of it.
        primary_key_their_signature = bytes.fromhex(request["signed_primary_key"])
        primary_key = self._route.nodes[-1].e2e_primary_key
        target_certificate = self._stack._layer4._cached_certificates[self._route.nodes[-1].identifier]
        target_static_public_key = target_certificate.public_key

        # Verify the signature of the hashed primary key.
        verification = Signer.verify(
            their_static_public_key=target_static_public_key,
            message=primary_key,
            signature=primary_key_their_signature,
            target_id=self._route.nodes[-2].identifier)

        if not verification:
            logging.error(f"Invalid signature from {address}")
            self._route.nodes[-1].state = RouteNodeState.Rejected
            return

        # Mark the target node as accepted.
        self._route.nodes[-1].state = RouteNodeState.Accepted

    def _handle_tunnel_reject(self, address: IPv6Address, request: Json) -> None:
        # Mark the pending node as rejected, so the initial loop can continue.
        self._route.nodes[-1].state = RouteNodeState.Rejected

    def _handle_forward_message(self, address: IPv6Address, request: Json) -> None:
        # Get the connection token and route token from the request.
        token = bytes.fromhex(request["token"])
        route_token = bytes.fromhex(request["route_token"])

        # Determine the connection object and tunnel key.
        connection = self._stack._layer4._conversations[token]

        # If this is the client node, then forwarding a message requires adding all 3 layers of encryption.
        if "self" in request.keys():
            for node in self._route.nodes[1:]:
                tunnel_key = node.e2e_primary_key
                dumped_req = SafeJson.dumps(request)
                request = {
                    "command": Layer2Protocol.ForwardMessage.value,
                    "data": SymmetricEncryption.encrypt(data=dumped_req, key=tunnel_key).hex()}
            self._send(self._stack._layer4._conversations[self._route.entry_token], request)

        # If the client node is receiving a tunneled message, remove all 3 layers of encryption.
        elif token == self._route.entry_token:
            for node in self._route.nodes[1:]:
                tunnel_key = node.e2e_primary_key
                dumped_data = SymmetricEncryption.decrypt(data=bytes.fromhex(request["data"]), key=tunnel_key)
                request = SafeJson.loads(dumped_data)
            self._handle_command(address, request)

        # For the forward direction, remove a layer of encryption and send the request to the next node.
        elif token in self._route_forward_token_map:
            # Remove a layer of encryption and load the nested request as JSON.
            tunnel_key = self._tunnel_keys[route_token].primary_key
            dumped_data = SymmetricEncryption.decrypt(data=bytes.fromhex(request["data"]), key=tunnel_key)
            request = SafeJson.loads(dumped_data)

            # Get the next node's token, and send the request to connection to it.
            next_node_token = self._route_forward_token_map[token]
            next_node_connection = self._stack._layer4._conversations[next_node_token]
            self._send(next_node_connection, request)

        # For the reverse direction, add a layer of encryption and send the request to the previous node.
        else:
            # Add a layer of encryption and load the wrapped request as JSON.
            tunnel_key = self._tunnel_keys[route_token].primary_key
            dumped_data = SafeJson.dumps(request)
            request = {
                "command": Layer2Protocol.ForwardMessage.value,
                "data": SymmetricEncryption.encrypt(data=dumped_data, key=tunnel_key).hex()}

            # Get the previous node's token, and send the request to connection to it.
            prev_node_token = self._route_reverse_token_map[token]
            prev_node_connection = self._stack._layer4._conversations[prev_node_token]
            self._send(prev_node_connection, request)

    def _handle_internet_send(self, address: IPv6Address, request: Json) -> None:
        # Get the route token from the request.
        route_token = bytes.fromhex(request["route_token"])

        # Create a (temporary) target TCP socket and send the HTTP request.
        target_socket = Socket()
        target_socket.connect((request["target_address"], request["target_port"]))
        target_socket.sendall(bytes.fromhex(request["http_request"]))

        # Receive the HTTP response and tunnel it backwards.
        response = target_socket.recv(4096)
        self._tunnel_message_backwards(route_token, {
            "command": Layer2Protocol.InternetRecv.value,
            "data": response.hex(),
            "response_id": request["request_id"]})

    def _handle_internet_recv(self, address: IPv6Address, request: Json) -> None:
        # Push the response upto Layer 1.
        ...

    def _tunnel_message_forwards(self, request: Json) -> None:
        """
        Only the client ever tunnels a message forwards. This is because the client is the only node who knows all the
        other nodes in the route, and is therefore the only node who has tunnel keys for every other node. To tunnel a
        message forwards, the client encrypts the message with each tunnel key, adding information about the next node
        to the message each time.

        The message is then sent to the next node, who decrypts the message and forwards it to the next node. This
        process is repeated until the message reaches the final node. The final node will then process the message,
        which may involve sending data to the Internet.

        Arguments
            request: The message to tunnel forwards.
        """

        wrapped_request = {
            "command": Layer2Protocol.ForwardMessage.value,
            "data": SafeJson.dumps(request)}

        self._send(self._self_connection, wrapped_request)

    def _tunnel_message_backwards(self, route_token: Bytes, request: Json) -> None:
        wrapped_request = {
            "command": Layer2Protocol.ForwardMessage.value,
            "data": SafeJson.dumps(request),
            "route_token": route_token.hex()}

        self._send(self._self_connection, wrapped_request)
