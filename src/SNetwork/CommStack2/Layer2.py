from __future__ import annotations

import logging, os
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address

from SNetwork.CommStack2.LayerN import LayerN, LayerNProtocol, Connection
from SNetwork.CommStack2.Layer3 import Layer3
from SNetwork.CommStack2.Layer4 import Layer4
from SNetwork.Config import LAYER_2_PORT
from SNetwork.Crypt.KEM import KEM
from SNetwork.Crypt.Sign import Signer
from SNetwork.Crypt.AsymmetricKeys import PubKey, SecKey
from SNetwork.Utils.Types import Int, Json, Bytes, Dict, Optional, List


@dataclass(kw_only=True)
class Route:
    route_token: Bytes
    entry_token: Bytes
    nodes: List[RouteNode]


class RouteNodeState(Enum):
    Waiting = 0x00
    Accepted = 0x01
    Rejected = 0x02


@dataclass(kw_only=True)
class RouteNode:
    address: IPv6Address
    identifier: Bytes
    challenge: Bytes
    ephemeral_public_key: Optional[PubKey] = field(default=None)
    e2e_primary_key: Optional[Bytes] = field(default=None)
    state: RouteNodeState = field(default=RouteNodeState.Waiting)


@dataclass
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


class Layer2(LayerN):
    _layer3: Layer3
    _layer4: Layer4

    _route: Optional[Route]
    _route_forward_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _route_reverse_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _tunnel_keys: Dict[Bytes, TunnelKeyGroup]     # Route ID => Tunnel Key Group

    def __init__(self, layer3: Layer3, layer4: Layer4) -> None:
        super().__init__()
        self._layer3 = layer3
        self._layer4 = layer4

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
            case _:
                logging.error(f"Invalid command: {request["command"]}")

    def _send(self, connection: Connection, data: Json) -> None:
        pass

    @property
    def _port(self) -> Int:
        return LAYER_2_PORT

    def create_route(self) -> None:
        ...

    def _handle_extend_connection(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Extending a connection to {address}")

        # Get the target address and identifier.
        target_address = IPv6Address(request["target_address"])
        target_identifier = bytes.fromhex(request["target_identifier"])
        route_token = bytes.fromhex(request["route_token"])

        # Connect to this target.
        extended_connection = self._layer4.connect(target_address, target_identifier)

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

        # Create an ephemeral public key, and sign it and the challenge with the primary key.
        challenge = bytes.fromhex(request["challenge"])
        tunnel_ephemeral_public_key_pair = KEM.generate_key_pair()
        signature = Signer.sign(self._layer4._this_static_secret_key, challenge + tunnel_ephemeral_public_key_pair.public_key.der)
        self._tunnel_keys[route_token] = TunnelKeyGroup(tunnel_ephemeral_public_key_pair.secret_key)

        # Send the ephemeral public key and signature back to the target's current final node.
        self._tunnel_message_backwards(route_token, {
            "command": Layer2Protocol.TunnelEphemeralKey.value,
            "ephemeral_public_key": tunnel_ephemeral_public_key_pair.public_key.der.hex(),
            "signature": signature.hex(),
        })

    def _handle_tunnel_ephemeral_key(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received a tunnel ephemeral key from {address}")
        token = bytes.fromhex(request["token"])

        # Determine crypto-related information regarding the target.
        target_ephemeral_public_key = PubKey.from_der(bytes.fromhex(request["ephemeral_public_key"]))
        target_signature = bytes.fromhex(request["signature"])
        target_certificate = self._layer4._cached_certificates[self._route.nodes[-1].identifier]
        target_static_public_key = target_certificate.public_key

        # Verify the signature of the challenge and ephemeral public key.
        if not Signer.verify(target_static_public_key, self._route.nodes[-1].challenge + target_ephemeral_public_key.der, target_signature):
            logging.error(f"Invalid signature from {address}")
            self._route.nodes[-1].state = RouteNodeState.Rejected
            return

        # Save the target's ephemeral public key and generate a primary key.
        self._route.nodes[-1].ephemeral_public_key = target_ephemeral_public_key
        self._route.nodes[-1].e2e_primary_key = os.urandom(32)

        # Wrap the primary key with the target's ephemeral public key, and tunnel it forwards.
        wrapped_primary_key = KEM.kem_wrap(target_ephemeral_public_key, self._route.nodes[-1].e2e_primary_key).encapsulated
        self._tunnel_message_forwards(self._layer4._conversations[token], self._route.route_token, {
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
        primary_key = KEM.kem_unwrap(this_ephemeral_secret_key, wrapped_primary_key).decapsulated
        self._tunnel_keys[route_token].primary_key = primary_key

        # Tunnel a signature of the hashed primary key back to the target for authentication.
        signed_primary_key = Signer.sign(self._layer4._this_static_secret_key, primary_key)
        self._tunnel_message_backwards(route_token, {
            "command": Layer2Protocol.TunnelAccept.value,
            "route_token": route_token.hex(),
            "signed_primary_key": signed_primary_key.hex(),
        })

    def _handle_tunnel_accept(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received a tunnel accept from {address}")

        # Get the primary key and the target node's signature of it.
        primary_key_their_signature = bytes.fromhex(request["signed_primary_key"])
        primary_key = self._route.nodes[-1].e2e_primary_key
        target_certificate = self._layer4._cached_certificates[self._route.nodes[-1].identifier]
        target_static_public_key = target_certificate.public_key

        # Verify the signature of the hashed primary key.
        if not Signer.verify(target_static_public_key, primary_key, primary_key_their_signature):
            logging.error(f"Invalid signature from {address}")
            self._route.nodes[-1].state = RouteNodeState.Rejected
            return

        # Mark the target node as accepted.
        self._route.nodes[-1].state = RouteNodeState.Accepted

    def _handle_tunnel_reject(self, address: IPv6Address, request: Json) -> None:
        # Mark the pending node as rejected, so the initial loop can continue.
        self._route.nodes[-1].state = RouteNodeState.Rejected

    def _handle_forward_message(self, address: IPv6Address, request: Json) -> None:
        ...

    def _tunnel_message_forwards(self, connection: Connection, route_token: Bytes, request: Json) -> None:
        ...

    def _tunnel_message_backwards(self, route_token: Bytes, request: Json) -> None:
        ...
