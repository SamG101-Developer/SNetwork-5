from __future__ import annotations

import random
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from threading import Thread
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, RawRequest, Connection, ConnectionState, \
    EncryptedRequest
from SNetwork.Config import TOLERANCE_CERTIFICATE_SIGNATURE, HOP_COUNT, DEFAULT_IPV6
from SNetwork.QuantumCrypto.Certificate import X509Certificate
from SNetwork.QuantumCrypto.QuantumKem import QuantumKem
from SNetwork.QuantumCrypto.QuantumSign import SignedMessagePair, QuantumSign
from SNetwork.QuantumCrypto.Symmetric import SymmetricEncryption
from SNetwork.QuantumCrypto.Timestamp import Timestamp
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Socket import Socket

if TYPE_CHECKING:
    from SNetwork.Utils.Types import Bytes, Optional, Dict, Int, List, Bool
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.Managers.KeyManager import KeyStoreData


class TunnelRejectionReason(Enum):
    NodeUnreachable = 0x00
    NodeDecision = 0x01


@dataclass(kw_only=True)
class Route:
    """
    A route is a series of nodes that form a path from one point to another in the network.

    Attributes:
        - route_token: The token that identifies the route. Managed by the route owner.
        - entry_token: The token that identifies the connection to the entry node in the route.
        - nodes: A list of connections that make up the route.
        - candidate_node: The connection that is being considered for inclusion in the route.
    """

    route_token: Bytes  # Route identifier
    entry_token: Bytes  # Connection identifier to the entry node
    nodes: List[Connection] = field(default_factory=list, init=False)
    candidate_node: Optional[Connection] = field(default=None, init=False)
    ready: bool = field(default=False, init=False)


class Layer2(LayerN):
    """
    Layer 2 of the Communication Stack is the "Routing Layer". This layer is responsible for setting up and maintaining
    the route between the client and the exit node. The client is the node that sends data to the exit node, and the
    exit node is the node that sends data to the Internet.

    The entry, intermediary and exit nodes are all connected to each other via Layer 4 connections. The client is
    exchanges tunnel keys with each node in the route.

    Attributes:
        _my_route: The current route between the client and the exit node.
        _route_forward_token_map: A mapping of connection tokens to the next node's connection token.
        _route_reverse_token_map: A mapping of connection tokens to the previous node's connection token.
        _participating_route_keys: A mapping of route tokens to the primary key of the tunnel.
    """

    _my_route: Optional[Route]
    _route_forward_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _route_reverse_token_map: Dict[Bytes, Bytes]  # Connection Token => Connection Token
    _participating_route_keys: Dict[Bytes, Bytes]  # Connection Token => Primary Key
    _self_conn: Optional[Connection]

    @dataclass(kw_only=True)
    class RouteExtensionRequest(RawRequest):
        route_tok: Bytes
        route_owner_epk: Bytes
        next_node_ip: IPv6Address
        next_node_port: Int
        next_node_id: Bytes

    @dataclass(kw_only=True)
    class TunnelJoinRequest(RawRequest):
        route_token: Bytes
        route_owner_epk: Bytes

    @dataclass(kw_only=True)
    class TunnelJoinAccept(RawRequest):
        route_token: Bytes
        acceptor_cert: X509Certificate
        kem_wrapped_e2e_primary_key: Bytes
        sig: SignedMessagePair

    @dataclass(kw_only=True)
    class TunnelJoinReject(RawRequest):
        route_token: Bytes
        reason: TunnelRejectionReason

    @dataclass(kw_only=True)
    class TunnelDataForward(RawRequest):
        data: Bytes

    @dataclass(kw_only=True)
    class TunnelDataBackward(RawRequest):
        data: Bytes

    def __init__(self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket) -> None:
        super().__init__(stack, node_info, socket, isolated_logger(LoggerHandlers.LAYER_2))

        self._my_route = None
        self._route_forward_token_map = {}
        self._route_reverse_token_map = {}
        self._participating_route_keys = {}
        self._logger.info("Layer 2 Ready")

    def create_route(self) -> None:
        # Check there are enough cached nodes to create a route.
        while len(self._stack._layerD._node_cache) < HOP_COUNT + 1:
            self._logger.warning("Not enough nodes in the cache to create a route...")
            time.sleep(1)

        # Get the cache and remove this node from it.
        cache = self._stack._layerD._node_cache.copy()
        cache = [node for node in cache if node[2] != self._self_node_info.identifier]

        # Add this node as the first node in the route (self-send to tunnel onwards).
        self._logger.info("Creating pre-entry self connection...")

        self._self_conn = Connection(
            peer_ip=IPv6Address(DEFAULT_IPV6), peer_port=self._self_node_info.port,
            peer_id=self._self_node_info.identifier, conn_tok=secrets.token_bytes(32) + Timestamp.generate_time_stamp(),
            conn_state=ConnectionState.ConnectionOpen, e2e_key=SymmetricEncryption.generate_key())
        self._stack._layer4._conversations[self._self_conn.conn_tok] = self._self_conn

        # Create the route object.
        self._logger.info("Creating route object...")
        self._my_route = Route(route_token=secrets.token_bytes(32), entry_token=self._self_conn.conn_tok)
        self._my_route.nodes.append(self._self_conn)
        self._participating_route_keys[self._my_route.entry_token] = self._self_conn.e2e_key

        # For each hop in the route, create a connection to the next node.
        while len(self._my_route.nodes) < HOP_COUNT + 1:
            random.shuffle(cache)

            # Generate the mock connection object to store candidate node information.
            self_ephemeral_key_pair = QuantumKem.generate_key_pair()
            candidate_info = cache.pop(0)
            candidate_node = Connection(
                peer_ip=candidate_info[0], peer_port=candidate_info[1], peer_id=candidate_info[2],
                conn_tok=secrets.token_bytes(32) + Timestamp.generate_time_stamp(),
                conn_state=ConnectionState.PendingConnection, self_epk=self_ephemeral_key_pair.public_key,
                self_esk=self_ephemeral_key_pair.secret_key)

            self._my_route.candidate_node = candidate_node
            self._logger.info(f"Chosen candidate node {candidate_node.peer_id.hex()}@{candidate_node.peer_ip}:{candidate_node.peer_port}.")

            # Send the extension request to the last node in the route so far.
            self._send_tunnel_forwards(Layer2.RouteExtensionRequest(
                route_tok=candidate_node.conn_tok, route_owner_epk=candidate_node.self_epk,
                next_node_ip=candidate_node.peer_ip, next_node_port=candidate_node.peer_port,
                next_node_id=candidate_node.peer_id), hops=len(self._my_route.nodes), for_route_setup=True)

            # Wait for either the candidate node to accept or reject the connection.
            while not (candidate_node.is_accepted() or candidate_node.is_rejected()):
                pass

            # Add the candidate node to the route.
            if candidate_node.is_accepted():
                self._logger.info(f"Candidate node {candidate_node.peer_id.hex()} joined the route.")
                self._my_route.nodes.append(candidate_node)

        self._my_route.ready = True
        self._logger.info("Route created successfully.")

    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: RawRequest, tun_req: Optional[EncryptedRequest] = None) -> None:
        # Deserialize the request and call the appropriate handler.

        # Get the token and state of the conversion for that token.
        token = req.conn_tok

        # Match the command to the appropriate handler.
        match req:

            # Handle a request to extend a route in the network.
            case Layer2.RouteExtensionRequest():
                thread = Thread(target=self._handle_route_extension_request, args=(peer_ip, peer_port, req, tun_req))
                thread.start()

            # Handle a request to join a tunnel.
            case Layer2.TunnelJoinRequest():
                thread = Thread(target=self._handle_tunnel_join_request, args=(peer_ip, peer_port, req))
                thread.start()

            # Handle a request to accept a tunnel join.
            case Layer2.TunnelJoinAccept():
                thread = Thread(target=self._handle_tunnel_join_accept, args=(peer_ip, peer_port, req))
                thread.start()

            # Handle a request to reject a tunnel join.
            case Layer2.TunnelJoinReject():
                thread = Thread(target=self._handle_tunnel_join_reject, args=(peer_ip, peer_port, req))
                thread.start()

            # Handle a request to forward data through a tunnel.
            case Layer2.TunnelDataForward():
                thread = Thread(target=self._handle_tunnel_data_forward, args=(peer_ip, peer_port, req, tun_req))
                thread.start()

            # Handle a request to backward data through a tunnel.
            case Layer2.TunnelDataBackward():
                thread = Thread(target=self._handle_tunnel_data_backward, args=(peer_ip, peer_port, req))
                thread.start()

            # Handle either an invalid command from a connected token.
            case _:
                self._logger.warning(f"Received invalid '{req}' request from '{req.conn_tok}'.")

    def _handle_route_extension_request(self, peer_ip: IPv6Address, peer_port: Int, req: RouteExtensionRequest, tun_req: EncryptedRequest) -> None:
        self._logger.info(f"Received route extension request from {peer_ip}:{peer_port}")
        self._logger.info(f"Sending route extension request to {req.next_node_ip}:{req.next_node_port}")

        # Create a new connection to the next node, specified by the request.
        prev_conn = self._stack._layer4._conversations[tun_req.conn_tok]
        next_conn = self._stack._layer4.connect(req.next_node_ip, req.next_node_port, req.next_node_id, conn_tok=req.route_tok)

        # If the connection cannot be made, reject the request.
        if not next_conn:
            rejection = Layer2.TunnelJoinReject(route_token=req.route_tok, reason=TunnelRejectionReason.NodeUnreachable)
            self._send_secure(prev_conn, rejection)
            return

        # Otherwise, the connection was successful, so send a TunnelJoinRequest to the next node.
        tunnel_join_request = Layer2.TunnelJoinRequest(route_token=req.route_tok, route_owner_epk=req.route_owner_epk)
        self._route_forward_token_map[prev_conn.conn_tok] = next_conn.conn_tok
        self._route_reverse_token_map[next_conn.conn_tok] = prev_conn.conn_tok
        self._send_secure(next_conn, tunnel_join_request)

    def _handle_tunnel_join_request(self, peer_ip: IPv6Address, peer_port: Int, req: TunnelJoinRequest) -> None:
        self._logger.info(f"Received tunnel join request from {peer_ip}:{peer_port}")

        # Get the connection object for this request.
        conn = self._stack._layer4._conversations[req.conn_tok]
        remote_session_id = req.route_token + req.route_owner_epk + conn.peer_id

        # Check if this node is eligible to accept the tunnel join request.
        if len(self._participating_route_keys) >= 3:
            rejection = Layer2.TunnelJoinReject(route_token=req.route_token, reason=TunnelRejectionReason.NodeDecision)
            self._send_secure(conn, rejection)
            return

        # Create a master key and kem-wrapped master key.
        kem = QuantumKem.encapsulate(public_key=req.route_owner_epk)
        kem_sig = QuantumSign.sign(skey=self._stack._layer4._self_static_skey, msg=kem.encapsulated, aad=remote_session_id)
        self._participating_route_keys[req.conn_tok] = kem.decapsulated  # use conn_tok so prev_node maps to route tunnel key instantly.

        # Create a new request responding to the handshake request.
        self._logger.info(f"Sending tunnel join accept to {peer_ip}:{peer_port}")
        self._send_secure(conn, Layer2.TunnelJoinAccept(
            route_token=req.route_token,
            acceptor_cert=self._stack._layer4._self_cert,
            kem_wrapped_e2e_primary_key=kem.encapsulated,
            sig=kem_sig))

    def _handle_tunnel_join_accept(self, peer_ip: IPv6Address, peer_port: Int, req: TunnelJoinAccept) -> None:
        self._logger.info(f"Received tunnel join accept from {peer_ip}:{peer_port}")

        # If the route token is not for this node's route, tunnel the request backwards.
        if self._my_route is None or self._my_route.candidate_node.conn_tok != req.route_token:
            prev_conn = self._stack._layer4._conversations[self._route_reverse_token_map[req.conn_tok]]
            self._send_tunnel_backwards(prev_conn, req)
            return

        # Check the node identifier on the acceptor certificate matches the candidate node.
        peer_id = req.acceptor_cert.tbs_certificate.subject["common_name"]
        if self._my_route.candidate_node.peer_id != peer_id:
            self._logger.error(f"Invalid node {peer_id.hex()} trying to join route.")
            self._my_route.candidate_node.conn_state = ConnectionState.ConnectionClosed
            return

        # Verify the certificate of the remote node.
        peer_static_pkey = req.acceptor_cert.tbs_certificate.subject_pk_info["public_key"]  # todo: remove cert from request and get it from pki
        if not QuantumSign.verify(pkey=peer_static_pkey, sig=req.acceptor_cert.signature_value, aad=peer_id, tolerance=TOLERANCE_CERTIFICATE_SIGNATURE):
            self._logger.error(f"Invalid certificate signature from node {peer_id.hex()}.")
            self._my_route.candidate_node.conn_state = ConnectionState.ConnectionClosed
            return

        # Verify the signature of the kem encapsulation.
        local_session_id = self._my_route.candidate_node.conn_tok + self._my_route.candidate_node.self_epk + self._my_route.nodes[-1].peer_id
        if not QuantumSign.verify(pkey=peer_static_pkey, sig=req.sig, aad=local_session_id):
            self._logger.error(f"Invalid kem signature from node {peer_id.hex()}.")
            self._my_route.candidate_node.conn_state = ConnectionState.ConnectionClosed
            return

        # Unwrap the kem encapsulation and set the e2e primary key for the tunnel.
        kem = QuantumKem.decapsulate(secret_key=self._my_route.candidate_node.self_esk, encapsulated=req.kem_wrapped_e2e_primary_key)
        self._my_route.candidate_node.e2e_key = kem.decapsulated
        self._my_route.candidate_node.conn_state = ConnectionState.ConnectionOpen

    def _handle_tunnel_join_reject(self, peer_ip: IPv6Address, peer_port: Int, req: TunnelJoinReject) -> None:
        # If the route token is not for this node's route, send the request backwards.
        if self._my_route is None or self._my_route.route_token != req.route_token:
            prev_conn_tok = self._route_reverse_token_map[req.conn_tok]
            prev_conn = self._stack._layer4._conversations[prev_conn_tok]
            self._send_secure(prev_conn, req)

        # Mark the candidate node as closed.
        self._logger.info(f"Node {req.conn_tok.hex()} rejected the tunnel join request.")
        self._my_route.candidate_node.conn_state = ConnectionState.ConnectionClosed

    def _handle_tunnel_data_forward(self, peer_ip: IPv6Address, peer_port: Int, req: TunnelDataForward, tun_req: EncryptedRequest) -> None:
        """!
        Nodes that handle a TunnelDataForward request are always relay nodes. However, because the route owner tells
        itself to send the tunnel request, the route owner is also acts as a pre-entry relay node that will handle this
        request.
        """

        # Unwrap the request and get the internal request object and send it over a secure connection.
        next_conn_tok = self._route_forward_token_map[tun_req.conn_tok]
        next_conn = self._stack._layer4._conversations[next_conn_tok]
        req = RawRequest.deserialize(req.data)
        self._send_secure(next_conn, req)

    def _handle_tunnel_data_backward(self, peer_ip: IPv6Address, peer_port: Int, req: TunnelDataBackward) -> None:
        """!
        Both relay nodes, and the route owner node will handle a TunnelDataBackward request. The relay nodes will add a
        layer of tunnel encryption to the request, and sendit onwards to the previous node. The route owner will unwrap
        all the layers of encryption and handle the internal request.
        """

        # Encrypt and send the request to the previous node in the route.
        if req.conn_tok in self._route_reverse_token_map:
            prev_conn_tok = self._route_reverse_token_map[req.conn_tok]
            prev_conn = self._stack._layer4._conversations[prev_conn_tok]

            self.attach_metadata(prev_conn, req)
            ciphertext = SymmetricEncryption.encrypt(data=req.serialize(), key=self._participating_route_keys[req.conn_tok])
            req = EncryptedRequest(conn_tok=req.conn_tok, ciphertext=ciphertext)
            req = Layer2.TunnelDataBackward(data=req.serialize())
            self._send_secure(prev_conn, req)
            return

        # Route owner decrypts all the layers of encryption and handles the internal request.
        if self._my_route is None or self._my_route.nodes[0].conn_tok != req.conn_tok:
            self._logger.warning(f"Received invalid tunnel data backward request from {req.conn_tok.hex()}.")
            return

        # Decrypt the request and handle it.
        for node in self._my_route.nodes:

            # todo: check every node tunnel token layered in the requests

            # Remove the layer of encryption from each node.
            req = RawRequest.deserialize(req.data)
            plaintext = SymmetricEncryption.decrypt(data=req.ciphertext, key=node.e2e_key)
            req = RawRequest.deserialize(plaintext)

            if not isinstance(req, Layer2.TunnelDataBackward):
                break

        # Handle the internal request.
        self._logger.info(f"Route owner fully unwrapped tunneled '{req}' request")
        self._send_secure(self._self_conn, req)

    def _send_tunnel_forwards(self, req: RawRequest, hops: Int = HOP_COUNT + 1, for_route_setup: Bool = False) -> None:
        while not self._my_route:
            continue
        while not for_route_setup and not self._my_route.ready:
            continue

        # Get the list of nodes in reverse order.
        node_list = list(reversed(self._my_route.nodes[:hops]))

        # Create the packaged request for the target node.
        self.attach_metadata(node_list[0], req)
        self._logger.info(f"Tunnelling '{req}' request {hops} hops forwards.")
        ciphertext = SymmetricEncryption.encrypt(data=req.serialize(), key=node_list[0].e2e_key)
        req = EncryptedRequest(conn_tok=node_list[0].conn_tok, ciphertext=ciphertext)

        # Layer the tunnel for subsequent nodes in the route.
        for node in node_list[1:]:
            req = Layer2.TunnelDataForward(data=req.serialize())
            self.attach_metadata(node, req)
            ciphertext = SymmetricEncryption.encrypt(data=req.serialize(), key=node.e2e_key)
            req = EncryptedRequest(conn_tok=node.conn_tok, ciphertext=ciphertext)

        # Send the request to the first node in the route.
        self._logger.info(f"Sending tunnelled message to first node in route: {self._my_route.nodes[0].peer_id.hex()}")
        self._send_secure(self._my_route.nodes[0], req)

    def _send_tunnel_backwards(self, prev_conn: Connection, req: RawRequest) -> None:
        # Create an encrypted request to send to the previous node.
        self.attach_metadata(prev_conn, req)
        ciphertext = SymmetricEncryption.encrypt(data=req.serialize(), key=self._participating_route_keys[prev_conn.conn_tok])
        req = EncryptedRequest(conn_tok=prev_conn.conn_tok, ciphertext=ciphertext)
        req = Layer2.TunnelDataBackward(data=req.serialize())
        self._send_secure(prev_conn, req)
