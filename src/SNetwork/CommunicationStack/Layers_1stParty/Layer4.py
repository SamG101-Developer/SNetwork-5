from __future__ import annotations

import secrets
from dataclasses import dataclass
from ipaddress import IPv6Address
from threading import Thread
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Isolation import cross_isolation, strict_isolation
from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, Connection, ConnectionState, RawRequest
from SNetwork.Config import TOLERANCE_CERTIFICATE_SIGNATURE
from SNetwork.QuantumCrypto.Certificate import X509Certificate
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.QuantumKem import QuantumKem
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign, SignedMessagePair
from SNetwork.QuantumCrypto.Timestamp import Timestamp
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Socket import Socket

if TYPE_CHECKING:
    from SNetwork.Utils.Types import Bytes, Optional, Dict, Int, Str
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.Managers.KeyManager import KeyStoreData


class Layer4(LayerN):
    """
    Layer 4 of the Communication Stack is the "Connection Layer". This layer is responsible for establishing secure
    connections between nodes in the network. It uses a combination of asymmetric keys, digital signatures, and key
    exchange mechanisms to ensure that the connection is secure and authenticated.

    Data sent in this layer is unencrypted, but authenticated. Once a connection is established, the end-to-end
    encryption is handled by the higher layers of the stack, specifically Layer 3 (DHT) and Layer 2 (Routing).

    Attributes:
        _self_id: The identifier of this node.
        _self_static_skey: The static secret key of this node.
        _self_cert: The X.509 certificate of this node.
        _conversations: A dictionary of active conversations with other nodes.
        _cached_certs: A dictionary of cached certificates for other nodes.
        _cached_pkeys: A dictionary of cached public keys for other nodes.
    """

    _self_id: Bytes
    _self_static_skey: Bytes
    _self_cert: X509Certificate
    _conversations: Dict[Bytes, Connection]
    _cached_certs: Dict[Bytes, X509Certificate]
    _cached_pkeys: Dict[Bytes, Bytes]

    @dataclass(kw_only=True)
    class ConnectionRequest(RawRequest):
        requester_cert: X509Certificate
        requester_epk: Bytes
        sig: SignedMessagePair

    @dataclass(kw_only=True)
    class ConnectionAccept(RawRequest):
        acceptor_cert: X509Certificate
        kem_wrapped_p2p_primary_key: Bytes
        sig: SignedMessagePair

    @dataclass(kw_only=True)
    class ConnectionAck(RawRequest):
        sig: SignedMessagePair

    @dataclass(kw_only=True)
    class ConnectionClose(RawRequest):
        reason: Str

    def __init__(self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket) -> None:
        super().__init__(stack, node_info, socket, isolated_logger(LoggerHandlers.LAYER_4))

        # Get the node identifier and static secret key.
        self._self_id = node_info.identifier
        self._self_static_skey = node_info.secret_key
        self._self_cert = node_info.certificate

        # Store the DHT node and conversation state.
        self._conversations = {}
        self._cached_certs = {}
        self._cached_pkeys = {}
        self._logger.info("Layer 4 Ready")

    @cross_isolation(4)
    def connect(self, peer_ip: IPv6Address, peer_port: Int, peer_id: Bytes, conn_tok: Bytes = b"") -> Optional[Connection]:
        """
        The "connect" method is called to create a UDP connection to another node in the network. This method handles
        the handshake, and authenticates and encrypts the connection. If the connection is accepted, a Connection object
        is returned, which can be used to send and receive data. Otherwise, None is returned.
        """

        # Generate a unique connection token for this connection.
        # Todo: Make a combination of this and that identifier, hashed? provides a linkage then
        conn_tok = (conn_tok or secrets.token_bytes(32)) + Timestamp.generate_time_stamp()
        remote_session_id = conn_tok + peer_id

        # Generate an ephemeral public key pair for this connection exclusively + sign.
        self_ephemeral_key_pair = QuantumKem.generate_key_pair()
        self_ephemeral_pkey_sig = QuantumSign.sign(
            skey=self._self_static_skey,
            msg=self_ephemeral_key_pair.public_key,
            aad=remote_session_id)

        # Create the Connection object to track the conversation.
        conn = Connection(
            peer_ip=peer_ip, peer_port=peer_port, peer_id=peer_id,
            self_epk=self_ephemeral_key_pair.public_key,
            self_esk=self_ephemeral_key_pair.secret_key,
            conn_tok=conn_tok, conn_state=ConnectionState.PendingConnection)
        self._conversations[conn.conn_tok] = conn

        # Create the JSON request to request a connection. Include the certificate and signed ephemeral public key.
        self._send(conn, Layer4.ConnectionRequest(
            requester_cert=self._self_cert,
            requester_epk=self_ephemeral_key_pair.public_key,
            sig=self_ephemeral_pkey_sig))

        # Wait for the connection to be accepted, rejected or closed, and return a value accordingly.
        while not (conn.is_rejected() or conn.is_accepted()):
            pass
        return conn if conn.is_accepted() else None

    @strict_isolation
    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: RawRequest) -> None:
        # Deserialize the request and call the appropriate handler.

        # Get the token and state of the conversion for that token.
        token = req.conn_tok
        state = self._conversations[token].conn_state if token in self._conversations else ConnectionState.NotConnected

        # Match the command to the appropriate handler.
        match req:

            # Handle a request to establish a connection from a non-connected token.
            case Layer4.ConnectionRequest() if state == ConnectionState.NotConnected:
                thread = Thread(target=self._handle_connection_request, args=(peer_ip, peer_port, req))
                thread.start()

            # Handle a response from a node that a connection request has been sent to.
            case Layer4.ConnectionAccept() if state == ConnectionState.PendingConnection:
                thread = Thread(target=self._handle_connection_accept, args=(req,))
                thread.start()

            # Handle a response from a node that has ACKed a connection acceptance.
            case Layer4.ConnectionAck() if state == ConnectionState.PendingConnection:
                thread = Thread(target=self._handle_connection_ack, args=(req,))
                thread.start()

            # Handle a close connection request from a node that a connection has been established with.
            case Layer4.ConnectionClose():
                thread = Thread(target=self._handle_connection_close, args=(req,))
                thread.start()

            # Handle either an invalid command from a connected token, or an invalid command/state combination.
            case _:
                self._logger.warning(f"Received invalid '{req}' request from '{req.conn_tok}'.")
                self._logger.warning(f"State: {state}")

    def _handle_connection_request(self, peer_ip: IPv6Address, peer_port: Int, req: Layer4.ConnectionRequest) -> None:
        # Create the Connection object to track the conversation.
        conn = Connection(
            peer_ip=peer_ip, peer_port=peer_port,
            peer_id=req.requester_cert.tbs_certificate.subject["common_name"],
            conn_tok=req.conn_tok, conn_state=ConnectionState.PendingConnection,
            peer_epk=req.requester_epk)

        # Create the local and remote session identifiers.
        local_session_id  = conn.conn_tok + self._self_id
        remote_session_id = conn.conn_tok + conn.peer_id
        peer_static_pkey = req.requester_cert.tbs_certificate.subject_pk_info["public_key"]

        # Verify the certificate of the remote node.
        if not QuantumSign.verify(pkey=peer_static_pkey, sig=req.requester_cert.signature_value, aad=conn.peer_id, tolerance=TOLERANCE_CERTIFICATE_SIGNATURE):
            self._send(conn, Layer4.ConnectionClose(reason="Invalid certificate."))
            return

        # Verify the signature of the ephemeral public key.
        if not QuantumSign.verify(pkey=peer_static_pkey, sig=req.sig, aad=local_session_id):
            self._send(conn, Layer4.ConnectionClose(reason="Invalid signature on ephemeral public key."))
            return

        # Validate the connection token's timestamp is within the tolerance.
        if not Timestamp.check_time_stamp(conn.conn_tok[-8:]):
            self._send(conn, Layer4.ConnectionClose(reason="Invalid connection token timestamp."))
            return

        # Cache the public key and certificate of the remote node.
        self._cached_pkeys[conn.peer_id] = peer_static_pkey
        self._cached_certs[conn.peer_id] = req.requester_cert

        # Create a master key and kem-wrapped master key.
        kem = QuantumKem.encapsulate(public_key=req.requester_epk)
        kem_sig = QuantumSign.sign(skey=self._self_static_skey, msg=kem.encapsulated, aad=remote_session_id)
        conn.e2e_key = kem.decapsulated

        # Create a new request responding to the handshake request.
        self._send(conn, Layer4.ConnectionAccept(
            acceptor_cert=self._self_cert,
            kem_wrapped_p2p_primary_key=kem.encapsulated,
            sig=kem_sig))

        # Clean up the connection object and mark it as pending.
        del conn.peer_epk
        conn.conn_state = ConnectionState.PendingConnection
        self._conversations[conn.conn_tok] = conn

    def _handle_connection_accept(self, req: Layer4.ConnectionAccept) -> None:
        # Get the connection object for this request.
        conn = self._conversations[req.conn_tok]

        # Create the local and remote session identifiers.
        local_session_id = conn.conn_tok + self._self_id
        remote_session_id = conn.conn_tok + conn.peer_id
        peer_static_pkey = req.acceptor_cert.tbs_certificate.subject_pk_info["public_key"]

        # Verify the certificate of the remote node.
        if not QuantumSign.verify(pkey=peer_static_pkey, sig=req.acceptor_cert.signature_value, aad=conn.peer_id, tolerance=TOLERANCE_CERTIFICATE_SIGNATURE):
            self._send(conn, Layer4.ConnectionClose(reason="Invalid certificate."))
            return

        # Verify the signature of the kem encapsulation.
        if not QuantumSign.verify(pkey=peer_static_pkey, sig=req.sig, aad=local_session_id):
            self._send(conn, Layer4.ConnectionClose(reason="Invalid signature on kem wrapped key."))
            return

        # Cache the public key and certificate of the remote node.
        self._cached_certs[conn.peer_id] = req.acceptor_cert
        self._cached_pkeys[conn.peer_id] = peer_static_pkey

        # Unwrap the master key and store it in the connection object.
        kem = QuantumKem.decapsulate(secret_key=conn.self_esk, encapsulated=req.kem_wrapped_p2p_primary_key)
        conn.e2e_key = kem.decapsulated

        # Send the ACK back to the other node, containing a signature of the master key.
        hash_e2e_primary_key = Hasher.hash(data=conn.e2e_key, algorithm=HashAlgorithm.SHA3_256)
        hash_e2e_primary_key_sig = QuantumSign.sign(skey=self._self_static_skey, msg=hash_e2e_primary_key, aad=remote_session_id)
        self._send(conn, Layer4.ConnectionAck(sig=hash_e2e_primary_key_sig))

        # Clean up the connection object and mark it as open.
        del conn.self_esk
        del conn.self_epk
        conn.conn_state = ConnectionState.ConnectionOpen
        self._logger.info(f"Connection established with {conn.peer_id.hex()}.")

    def _handle_connection_ack(self, req: Layer4.ConnectionAck) -> None:
        # Get the connection object for this request.
        conn = self._conversations[req.conn_tok]

        # Create the local and remote session identifiers.
        local_session_id = conn.conn_tok + self._self_id
        remote_session_id = conn.conn_tok + conn.peer_id
        self_static_pkey = self._cached_pkeys[conn.peer_id]

        # Verify the signature of the master key.
        hash_e2e_primary_key = Hasher.hash(data=conn.e2e_key, algorithm=HashAlgorithm.SHA3_256)
        if not QuantumSign.verify(pkey=self_static_pkey, sig=req.sig, raw=hash_e2e_primary_key, aad=local_session_id):
            self._send(conn, Layer4.ConnectionClose(reason="Invalid signature on master key."))
            return

        # Clean up the connection object and mark it as open.
        conn.conn_state = ConnectionState.ConnectionOpen
        self._logger.info(f"Connection established with {conn.peer_id.hex()}.")

    def _handle_connection_close(self, req: Layer4.ConnectionClose) -> None:
        # Get the connection object for this request.
        conn = self._conversations[req.conn_tok]
        self._logger.info(f"Connection closed: {req.reason}")

        # Clean up the connection object and mark it as closed.
        conn.conn_state = ConnectionState.ConnectionClosed
        del self._conversations[req.conn_tok]
