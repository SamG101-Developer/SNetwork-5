from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket
from threading import Thread
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, LayerNProtocol, Connection, InsecureRequest
from SNetwork.CommunicationStack.Isolation import strict_isolation
from SNetwork.QuantumCrypto.QuantumKem import QuantumKem
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign
from SNetwork.QuantumCrypto.Symmetric import SymmetricEncryption
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Json, Bytes, Dict, Optional, List, Str, Int

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.Managers.KeyManager import KeyStoreData


@dataclass(kw_only=True)
class Route:

    class Status(Enum):
        CandidateNodePending = 0x00
        CandidateNodeAccepted = 0x01
        CandidateNodeRejected = 0x02

    route_token: Bytes  # Route identifier
    entry_token: Bytes  # Connection identifier to the entry node
    nodes: List[Connection]
    candidate_node: Optional[Connection]
    status: Status


class Layer2Protocol(LayerNProtocol, Enum):
    ConnectionRouteExtendRequest = 0x01
    ConnectionRouteJoinRequest = 0x02
    ConnectionRouteJoinAcceptResponse = 0x03
    ConnectionRouteJoinRejectResponse = 0x04
    TunnelDataRequest = 0x06


@dataclass(kw_only=True)
class ConnectionRouteExtendRequest(InsecureRequest):
    route_token: Bytes
    next_address: Str
    next_port: Int
    next_identifier: Bytes
    route_owner_ephemeral_public_key: Bytes


@dataclass(kw_only=True)
class ConnectionRouteJoinRequest(InsecureRequest):
    route_token: Bytes
    route_owner_ephemeral_public_key: Bytes


@dataclass(kw_only=True)
class ConnectionRouteJoinRejectResponse(InsecureRequest):
    route_token: Bytes


@dataclass(kw_only=True)
class ConnectionRouteJoinAcceptResponse(InsecureRequest):
    route_token: Bytes
    acceptor_identifier: Bytes
    kem_master_key: Bytes
    signature: Bytes


@dataclass(kw_only=True)
class TunnelDataRequest(InsecureRequest):
    route_token: Bytes
    data: Bytes


class Layer2(LayerN):
    """
    Layer 2 of the Communication Stack is the "Routing Layer". This layer is responsible for setting up and maintaining
    the route between the client and the exit node. The client is the node that sends data to the exit node, and the
    exit node is the node that sends data to the Internet.

    The entry, intermediary and exit nodes are all connected to each other via Layer 4 connections. The client is
    exchanges tunnel keys with each node in the route.

    Attributes:
        _route: The current route between the client and the exit node.
        _route_forward_token_map: A mapping of connection tokens to the next node's connection token.
        _route_reverse_token_map: A mapping of connection tokens to the previous node's connection token.
        _external_tunnel_keys: A mapping of route tokens to tunnel keys.

    Methods:
        create_route: Creates a new route between the client and the exit node.
        forward_internet_data: Forwards data to the Internet.
        _handle_extend_connection: Handles a request to extend a connection for a route.
        _handle_tunnel_request: Handles a request to become part of the route.
        _handle_tunnel_ephemeral_key: Handles the ephemeral public key of the new candidate node for the route.
        _handle_tunnel_primary_key: Handles a wrapped primary key from the client.
        _handle_tunnel_accept: Handles the candidate node's acceptance of the route.
        _handle_tunnel_reject: Handles the candidate node's rejection of the route.
        _handle_forward_message: Handles a request to tunnel a message forwards.
        _handle_internet_send: Handles a request to tunnel data to the Internet.
        _handle_internet_recv: Handles a request to tunnel data from the Internet.
        _tunnel_message_forwards: Tunnels a message forwards (+ message prep).
        _tunnel_message_backwards: Tunnels a message backwards (+ message prep).
    """

    _route: Optional[Route]
    _route_forward_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _route_reverse_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _external_tunnel_keys: Dict[Bytes, Bytes]  # Route Token => Key

    def __init__(self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket) -> None:
        super().__init__(stack, node_info, Layer2Protocol, socket, isolated_logger(LoggerHandlers.LAYER_2))

        # Start listening on the socket for this layer.
        self._logger.debug("Layer 2 Ready")

    def create_route(self) -> None:
        ...

    @strict_isolation
    def _handle_command(self, address: IPv6Address, port: Int, data: Json) -> None:
        # Deserialize the request and call the appropriate handler.
        request_type = globals()[Layer2Protocol(data["protocol"]).name]
        request = request_type.deserialize(data)
        token = request.connection_token

        # Match the command to the appropriate handler.
        match request.protocol:

            # Handle a request, as the current final node, to extend the route to another node.
            case Layer2Protocol.ConnectionRouteExtendRequest:
                thread = Thread(target=self._handle_connection_route_extend_request, args=(request,))
                thread.start()

            # Handle a request to be attached to an existing route.
            case Layer2Protocol.ConnectionRouteJoinRequest:
                thread = Thread(target=self._handle_connection_route_join_request, args=(request,))
                thread.start()

            # Handle a candidate node's acceptance to joining the route.
            case Layer2Protocol.ConnectionRouteJoinAcceptResponse:
                thread = Thread(target=self._handle_connection_route_join_accept_response, args=(address, request))
                thread.start()

            # Handle a candidate node's rejection to joining the route.
            case Layer2Protocol.ConnectionRouteJoinRejectResponse:
                thread = Thread(target=self._handle_connection_route_join_reject_response, args=(address, request))
                thread.start()

            # Handle a request to tunnel data backwards or forwards in the route.
            case Layer2Protocol.TunnelDataRequest:
                thread = Thread(target=self._handle_tunnel_data_request, args=(address, request))
                thread.start()

            # Handle either an invalid command from a connected token, or an invalid command/state combination.
            case _:
                self._logger.warning(f"Received invalid command from token {token}.")

    @strict_isolation
    def _handle_connection_route_extend_request(self, request: ConnectionRouteExtendRequest) -> None:
        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[request.connection_token]

        # Create a connection to the new node as the route owner has requested.
        new_connection = self._stack._layer4.connect(
            address=IPv6Address(request.next_address),
            port=request.next_port,
            that_identifier=request.next_identifier)

        # A successful connection allows for the route join request to be sent.
        if new_connection:
            route_join_request = ConnectionRouteJoinRequest(
                route_token=request.route_token,
                route_owner_ephemeral_public_key=request.route_owner_ephemeral_public_key)
            self._send_secure(new_connection, route_join_request)

        # An unsuccessful connection results in the route owner being informed.
        else:
            rejection_response = ConnectionRouteJoinRejectResponse(route_token=request.route_token)
            self._send_tunnel_backwards(connection, rejection_response)

    @strict_isolation
    def _handle_connection_route_join_request(self, request: ConnectionRouteJoinRequest) -> None:
        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[request.connection_token]

        # Create a master key and kem-wrapped master key.
        kem_wrapped_key = QuantumKem.encapsulate(public_key=request.route_owner_ephemeral_public_key)
        signature = QuantumSign.sign(
            secret_key=self._stack._layer4._this_static_secret_key,
            message=self._stack._layer4._this_identifier + request.route_token + kem_wrapped_key.encapsulated,
            target_id=connection.connection_token + connection.that_identifier)
        self._external_tunnel_keys[request.route_token] = kem_wrapped_key.decapsulated

        # Check if they are involved in maximum number of routes.
        if len(self._external_tunnel_keys) < 3:
            self._send_secure(connection, ConnectionRouteJoinAcceptResponse(
                route_token=request.route_token,
                acceptor_identifier=self._stack._layer4._this_identifier,
                kem_master_key=kem_wrapped_key.encapsulated,
                signature=signature))
        else:
            self._send_secure(connection, ConnectionRouteJoinRejectResponse(
                route_token=request.route_token))

    @strict_isolation
    def _handle_connection_route_join_accept_response(self, request: ConnectionRouteJoinAcceptResponse) -> None:
        # If this node isn't the route owner, tunnel the message backwards.
        if not self._route or request.route_token != self._route.route_token:
            connection = self._stack._layer4._conversations[self._route_reverse_token_map[request.connection_token]]
            self._send_tunnel_backwards(connection, request)

        # Check the route token and candidate node are correct.
        if self._route.candidate_node != request.acceptor_identifier:
            self._logger.error("Invalid candidate node attempting to join the route.")
            return

        # Verify the signature of the candidate node.
        if not QuantumSign.verify(
                public_key=self._stack._layer4._cached_public_keys[request.acceptor_identifier],
                message=self._route.candidate_node.that_identifier + request.route_token + request.kem_master_key,
                signature=request.signature,
                target_id=self._route.route_token + self._route.nodes[-1].that_identifier):
            self._logger.error("Invalid signature from candidate node.")
            return

        # Decapsulate the master key and store it.
        self._route.candidate_node.e2e_primary_keys[0] = QuantumKem.decapsulate(
            secret_key=self._route.candidate_node.this_ephemeral_secret_key,
            encapsulated=request.kem_master_key).decapsulated
        self._route.nodes.append(self._route.candidate_node)

        # Mark the candidate node as accepted.
        self._route.status = Route.Status.CandidateNodeAccepted

    @strict_isolation
    def _handle_connection_route_join_reject_response(self, request: ConnectionRouteJoinRejectResponse) -> None:
        # If this node isn't the route owner, tunnel the message backwards.
        if not self._route or request.route_token != self._route.route_token:
            connection = self._stack._layer4._conversations[self._route_reverse_token_map[request.connection_token]]
            self._send_tunnel_backwards(connection, request)

        # Mark the candidate node as rejected, and the route builder will handle the circuit reset.
        self._route.status = Route.Status.CandidateNodeRejected

    @strict_isolation
    def _handle_tunnel_data_request(self, request: TunnelDataRequest) -> None:
        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[request.connection_token]

        # Client receive (remove all layers of encryption).
        if self._route and self._route.route_token == request.route_token:
            for route_node in self._route.nodes:
                request.data = SymmetricEncryption.decrypt(data=request.data, key=route_node.e2e_primary_keys[0])
            self._handle_command(connection.that_address, connection.that_port, InsecureRequest.deserialize_to_json(request.data))

        # Tunnel a message backwards (add a layer of encryption).
        else:
            self._send_tunnel_backwards(connection, request)

    @strict_isolation
    def _send_tunnel_forwards(self, connection: Connection, tunnel_request: InsecureRequest) -> None:
        # The client will tunnel the message forwards to a node in the route.
        tunnel_request = self._prep_data(connection, tunnel_request)
        for route_node in self._route.nodes:
            request_data = SymmetricEncryption.encrypt(data=tunnel_request.serialize(), key=route_node.e2e_primary_keys[0])
            tunnel_request = TunnelDataRequest(route_token=self._route.route_token, data=request_data)

        # Send the data to the entry node.
        entry_connection = connection
        self._send_secure(entry_connection, tunnel_request)

    @strict_isolation
    def _send_tunnel_backwards(self, connection: Connection, request: InsecureRequest, route_token: Bytes) -> None:
        # A route node wil tunnel the message backwards to the client.
        request_data = self._prep_data(connection, request).serialize()
        request_data = SymmetricEncryption.encrypt(data=request_data, key=self._external_tunnel_keys[route_token])

        # Wrap the data in a tunnel request and send it to the previous node.
        tunnel_request = TunnelDataRequest(route_token=route_token, data=request_data)
        self._send_secure(connection, tunnel_request)
