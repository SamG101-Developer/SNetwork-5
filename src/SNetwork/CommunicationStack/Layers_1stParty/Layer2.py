from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket
from threading import Thread
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, LayerNProtocol, Connection, RawRequest
from SNetwork.CommunicationStack.Isolation import strict_isolation
from SNetwork.QuantumCrypto.QuantumKem import QuantumKem
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign, SignedMessagePair
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
class ConnectionRouteExtendRequest(RawRequest):
    route_token: Bytes
    next_address: Str
    next_port: Int
    next_identifier: Bytes
    route_owner_ephemeral_public_key: Bytes


@dataclass(kw_only=True)
class ConnectionRouteJoinRequest(RawRequest):
    route_token: Bytes
    route_owner_ephemeral_public_key: Bytes


@dataclass(kw_only=True)
class ConnectionRouteJoinRejectResponse(RawRequest):
    route_token: Bytes


@dataclass(kw_only=True)
class ConnectionRouteJoinAcceptResponse(RawRequest):
    route_token: Bytes
    acceptor_identifier: Bytes
    kem_master_key: Bytes
    signature: SignedMessagePair


@dataclass(kw_only=True)
class TunnelDataRequest(RawRequest):
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
    """

    _route: Optional[Route]
    _route_forward_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _route_reverse_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _external_tunnel_keys: Dict[Bytes, Bytes]  # Route Token => Key

    def __init__(self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket) -> None:
        super().__init__(stack, node_info, Layer2Protocol, socket, isolated_logger(LoggerHandlers.LAYER_2))

        # Start listening on the socket for this layer.
        self._logger.info("Layer 2 Ready")

    def create_route(self) -> None:
        ...

    @strict_isolation
    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: Json) -> None:
        # Deserialize the request and call the appropriate handler.
        request_type = globals()[Layer2Protocol(req["protocol"]).name]
        request = request_type.deserialize(req)
        token = request.conn_tok

        # Match the command to the appropriate handler.
        match request.proto:

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
                thread = Thread(target=self._handle_connection_route_join_accept_response, args=(peer_ip, request))
                thread.start()

            # Handle a candidate node's rejection to joining the route.
            case Layer2Protocol.ConnectionRouteJoinRejectResponse:
                thread = Thread(target=self._handle_connection_route_join_reject_response, args=(peer_ip, request))
                thread.start()

            # Handle a request to tunnel data backwards or forwards in the route.
            case Layer2Protocol.TunnelDataRequest:
                thread = Thread(target=self._handle_tunnel_data_request, args=(peer_ip, request))
                thread.start()

            # Handle either an invalid command from a connected token, or an invalid command/state combination.
            case _:
                self._logger.warning(f"Received invalid command from token {token}.")

    @strict_isolation
    def _handle_connection_route_extend_request(self, request: ConnectionRouteExtendRequest) -> None:
        # Get the connection object for this request.
        metdata = request.meta
        connection = self._stack._layer4._conversations[metdata.conn_tok]

        # Create a connection to the new node as the route owner has requested.
        new_connection = self._stack._layer4.connect(
            peer_ip=IPv6Address(request.next_address),
            peer_port=request.next_port,
            peer_id=request.next_identifier)

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
        metdata = request.meta
        connection = self._stack._layer4._conversations[metdata.conn_tok]

        # Create a master key and kem-wrapped master key.
        kem_wrapped_key = QuantumKem.encapsulate(public_key=request.route_owner_ephemeral_public_key)
        signature = QuantumSign.sign(
            skey=self._stack._layer4._self_static_skey,
            msg=self._stack._layer4._self_id + request.route_token + kem_wrapped_key.encapsulated,
            aad=connection.conn_tok + connection.peer_id)
        self._external_tunnel_keys[request.route_token] = kem_wrapped_key.decapsulated

        # Check if they are involved in maximum number of routes.
        if len(self._external_tunnel_keys) < 3:
            self._send_secure(connection, ConnectionRouteJoinAcceptResponse(
                route_token=request.route_token,
                acceptor_identifier=self._stack._layer4._self_id,
                kem_master_key=kem_wrapped_key.encapsulated,
                signature=signature))
        else:
            self._send_secure(connection, ConnectionRouteJoinRejectResponse(
                route_token=request.route_token))

    @strict_isolation
    def _handle_connection_route_join_accept_response(self, request: ConnectionRouteJoinAcceptResponse) -> None:
        metdata = request.meta

        # If this node isn't the route owner, tunnel the message backwards.
        if not self._route or request.route_token != self._route.route_token:
            connection = self._stack._layer4._conversations[self._route_reverse_token_map[metdata.conn_tok]]
            self._send_tunnel_backwards(connection, request)

        # Check the route token and candidate node are correct.
        if self._route.candidate_node != request.acceptor_identifier:
            self._logger.error("Invalid candidate node attempting to join the route.")
            return

        # Verify the signature of the candidate node.
        if not QuantumSign.verify(
                pkey=self._stack._layer4._cached_pkeys[request.acceptor_identifier],
                sig=request.signature,
                aad=self._route.route_token + self._route.nodes[-1].peer_id):
            self._logger.error("Invalid signature from candidate node.")
            return

        # Decapsulate the master key and store it.
        self._route.candidate_node.e2e_primary_key = QuantumKem.decapsulate(
            secret_key=self._route.candidate_node.self_ephemeral_skey,
            encapsulated=request.kem_master_key).decapsulated
        self._route.nodes.append(self._route.candidate_node)

        # Mark the candidate node as accepted.
        self._route.status = Route.Status.CandidateNodeAccepted

    @strict_isolation
    def _handle_connection_route_join_reject_response(self, request: ConnectionRouteJoinRejectResponse) -> None:
        metdata = request.meta

        # If this node isn't the route owner, tunnel the message backwards.
        if not self._route or request.route_token != self._route.route_token:
            connection = self._stack._layer4._conversations[self._route_reverse_token_map[metdata.conn_tok]]
            self._send_tunnel_backwards(connection, request)

        # Mark the candidate node as rejected, and the route builder will handle the circuit reset.
        self._route.status = Route.Status.CandidateNodeRejected

    @strict_isolation
    def _handle_tunnel_data_request(self, request: TunnelDataRequest) -> None:
        metdata = request.meta

        # Get the connection object for this request.
        connection = self._stack._layer4._conversations[metdata.conn_tok]

        # Client receive (remove all layers of encryption).
        if self._route and self._route.route_token == request.route_token:
            for route_node in self._route.nodes:
                request.data = SymmetricEncryption.decrypt(data=request.data, key=route_node.e2e_primary_key)
            self._handle_command(connection.peer_ip, connection.peer_port, RawRequest.deserialize_to_json(request.data))

        # Tunnel a message backwards (add a layer of encryption).
        else:
            self._send_tunnel_backwards(connection, request)

    @strict_isolation
    def _send_tunnel_forwards(self, connection: Connection, tunnel_request: RawRequest) -> None:
        # The client will tunnel the message forwards to a node in the route.
        tunnel_request = self._prep_data(connection, tunnel_request)
        for route_node in self._route.nodes:
            request_data = SymmetricEncryption.encrypt(data=tunnel_request.serialize(), key=route_node.e2e_primary_key)
            tunnel_request = TunnelDataRequest(route_token=self._route.route_token, data=request_data)

        # Send the data to the entry node.
        entry_connection = connection
        self._send_secure(entry_connection, tunnel_request)

    @strict_isolation
    def _send_tunnel_backwards(self, connection: Connection, request: RawRequest, route_token: Bytes) -> None:
        # A route node wil tunnel the message backwards to the client.
        request_data = self._prep_data(connection, request).serialize()
        request_data = SymmetricEncryption.encrypt(data=request_data, key=self._external_tunnel_keys[route_token])

        # Wrap the data in a tunnel request and send it to the previous node.
        tunnel_request = TunnelDataRequest(route_token=route_token, data=request_data)
        self._send_secure(connection, tunnel_request)
