from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket
from threading import Thread
from typing import TYPE_CHECKING
import secrets

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, LayerNProtocol, Connection, ConnectionState, RawRequest
from SNetwork.CommunicationStack.Isolation import cross_isolation, strict_isolation
from SNetwork.Config import TOLERANCE_CERTIFICATE_SIGNATURE
from SNetwork.QuantumCrypto.Certificate import X509Certificate
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.QuantumKem import QuantumKem
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign, SignedMessagePair
from SNetwork.QuantumCrypto.Symmetric import SymmetricEncryption
from SNetwork.QuantumCrypto.Timestamp import Timestamp
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers

if TYPE_CHECKING:
    from SNetwork.Utils.Types import Bytes, Optional, Dict, Int, Str
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.Managers.KeyManager import KeyStoreData


class Layer4Protocol(LayerNProtocol, Enum):
    ConnectionRequest = 0x01
    ConnectionAccept = 0x02
    ConnectionClose = 0x03
    ConnectionRotateKey = 0x04
    ConnectionData = 0x05


@dataclass(kw_only=True)
class ConnectionRequest(RawRequest):
    certificate: X509Certificate
    ephemeral_public_key: Bytes
    signed_epk: SignedMessagePair


@dataclass(kw_only=True)
class ConnectionAccept(RawRequest):
    certificate: X509Certificate
    kem_master_key: Bytes
    signature: SignedMessagePair


@dataclass(kw_only=True)
class ConnectionClose(RawRequest):
    reason: Str


@dataclass(kw_only=True)
class ConnectionRotateKey(RawRequest):
    cur_key_hashed: Bytes
    new_key_wrapped: Bytes
    after: Int


class Layer4(LayerN):
    """
    Layer 4 of the Communication Stack is the "Connection Layer". This layer is responsible for establishing secure
    connections between nodes in the network. It uses a combination of asymmetric keys, digital signatures, and key
    exchange mechanisms to ensure that the connection is secure and authenticated.

    Data sent in this layer is unencrypted, but authenticated. Once a connection is established, the end-to-end
    encryption is handled by the higher layers of the stack, specifically Layer 3 (DHT) and Layer 2 (Routing).

    Attributes:
        _this_identifier: The identifier of this node.
        _this_static_secret_key: The static secret key of this node.
        _this_certificate: The X.509 certificate of this node.
        _conversations: A dictionary of active conversations with other nodes.
        _cached_certificates: A dictionary of cached certificates for other nodes.
        _cached_public_keys: A dictionary of cached public keys for other nodes.

    Methods:
        connect: Initiate a connection to a remote node.
        _handle_command: Handles incoming commands from other nodes.
        _handle_connection_request: Handles a connection request from a remote node.
        _handle_connection_accept: Handles a connection accept from a remote node.
        _handle_connection_close: Handles a connection close from a remote node.
        _handle_rotate_key: Handles a request to rotate the session key.
    """

    _this_identifier: Bytes
    _this_static_secret_key: Bytes
    _this_certificate: X509Certificate
    _conversations: Dict[Bytes, Connection]
    _cached_certificates: Dict[Bytes, X509Certificate]
    _cached_public_keys: Dict[Bytes, Bytes]

    def __init__(self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket) -> None:
        super().__init__(stack, node_info, Layer4Protocol, socket, isolated_logger(LoggerHandlers.LAYER_4))

        # Get the node identifier and static secret key.
        self._this_identifier = node_info.identifier
        self._this_static_secret_key = node_info.secret_key
        self._this_certificate = node_info.certificate
        self._this_nonce = 0

        # Store the DHT node and conversation state.
        self._conversations = {}
        self._cached_certificates = {}
        self._cached_public_keys = {}
        self._logger.info("Layer 4 Ready")

    @cross_isolation(4)
    def connect(self, address: IPv6Address, port: Int, that_identifier: Bytes) -> Optional[Connection]:
        """
        The "connect" method is called to create a UDP connection to another node in the network. This method handles
        the handshake, and authenticates and encrypts the connection. If the connection is accepted, a Connection object
        is returned, which can be used to send and receive data. Otherwise, None is returned.
        """

        # Generate a unique connection token for this connection.
        # Todo: Make a combination of this and that identifier, hashed? provides a linkage then
        connection_token = secrets.token_bytes(32) + Timestamp.generate_time_stamp()

        # Generate an ephemeral public key pair for this connection exclusively + sign.
        this_ephemeral_key_pair = QuantumKem.generate_key_pair()
        this_ephemeral_public_key_signed = QuantumSign.sign(
            skey=self._this_static_secret_key,
            msg=this_ephemeral_key_pair.public_key,
            id_=connection_token + that_identifier)

        # Create the Connection object to track the conversation.
        connection = Connection(
            that_address=address, that_port=port,
            that_identifier=that_identifier,
            this_ephemeral_public_key=this_ephemeral_key_pair.public_key,
            this_ephemeral_secret_key=this_ephemeral_key_pair.secret_key,
            connection_token=connection_token,
            connection_state=ConnectionState.PendingConnection)
        self._conversations[connection.connection_token] = connection

        # Create the JSON request to request a connection. Include the certificate and signed ephemeral public key.
        self._send(connection, ConnectionRequest(
            certificate=self._this_certificate,
            ephemeral_public_key=this_ephemeral_key_pair.public_key,
            signed_epk=this_ephemeral_public_key_signed))

        # Wait for the connection to be accepted, rejected or closed, and return a value accordingly.
        while not (connection.is_rejected() or connection.is_accepted()):
            pass
        return connection if connection.is_accepted() else None

    @strict_isolation
    def rotate_key(self, connection: Connection) -> None:
        # Generate a new master key and wrap it with the current key.
        new_key = SymmetricEncryption.generate_key()
        current_key = list(connection.e2e_primary_keys.values())[-1]
        wrapped_key = SymmetricEncryption.wrap_new_key(current_key=current_key, new_key=new_key)

        # Hash the current key and increment the key rotation counter.
        current_key_hashed = Hasher.hash(data=current_key, algorithm=HashAlgorithm.SHA3_256())
        connection.key_rotations += 1
        connection.e2e_primary_keys[connection.key_rotations * 100] = new_key

        # Create the JSON request to rotate the session key.
        self._send_secure(connection, ConnectionRotateKey(
            cur_key_hashed=current_key_hashed,
            new_key_wrapped=wrapped_key,
            after=connection.key_rotations))

    @strict_isolation
    def _handle_command(self, address: IPv6Address, port: Int, request: RawRequest) -> None:
        # Deserialize the request and call the appropriate handler.

        # Get the token and state of the conversion for that token.
        token = request.request_metadata.connection_token
        state = self._conversations[token].connection_state if token in self._conversations else ConnectionState.NotConnected

        # Match the command to the appropriate handler.
        match request.request_metadata.protocol:

            # Handle a request to establish a connection from a non-connected token.
            case Layer4Protocol.ConnectionRequest if state == ConnectionState.NotConnected:
                thread = Thread(target=self._handle_connection_request, args=(address, port, request))
                thread.start()

            # Handle a response from a node that a connection request has been sent to.
            case Layer4Protocol.ConnectionAccept if state == ConnectionState.PendingConnection:
                thread = Thread(target=self._handle_connection_accept, args=(request,))
                thread.start()

            # Handle a close connection request from a node that a connection has been established with.
            case Layer4Protocol.ConnectionClose:
                thread = Thread(target=self._handle_connection_close, args=(request,))
                thread.start()

            # Handle a request to rotate the session key from a node that a connection has been established with.
            case Layer4Protocol.ConnectionRotateKey:
                thread = Thread(target=self._handle_rotate_key, args=(request,))
                thread.start()

            # Handle either an invalid command from a connected token, or an invalid command/state combination.
            case _:
                self._logger.warning(f"Received invalid command from token {token}.")
                self._logger.debug(f"State: {state}")

    def _handle_connection_request(self, address: IPv6Address, port: Int, request: ConnectionRequest) -> None:
        # Create the Connection object to track the conversation.
        metadata = request.request_metadata
        connection = Connection(
            that_address=address, that_port=port,
            that_identifier=request.certificate.tbs_certificate.subject["common_name"],
            connection_token=metadata.connection_token, connection_state=ConnectionState.PendingConnection,
            that_ephemeral_public_key=request.ephemeral_public_key)
        self._conversations[connection.connection_token] = connection
        local_session_id = connection.connection_token + self._this_identifier
        remote_session_id = connection.connection_token + connection.that_identifier

        # Verify the certificate of the remote node.
        d_pkey = request.certificate.tbs_certificate.issuer_pk_info["public_key"]
        if not QuantumSign.verify(pkey=d_pkey, sig=request.certificate.signature_value, id_=connection.that_identifier, tolerance=TOLERANCE_CERTIFICATE_SIGNATURE):
            self._send(connection, ConnectionClose(reason="Invalid certificate."))
            return
        that_static_public_key = request.certificate.tbs_certificate.subject_pk_info["public_key"]

        # Verify the signature of the ephemeral public key.
        if not QuantumSign.verify(pkey=that_static_public_key, sig=request.signed_epk, id_=local_session_id):
            self._send(connection, ConnectionClose(reason="Invalid signature on ephemeral public key."))
            return
        self._cached_public_keys[metadata.that_identifier] = that_static_public_key
        self._cached_certificates[metadata.that_identifier] = request.certificate

        # Validate the connection token's timestamp is within the tolerance.
        if not Timestamp.check_time_stamp(metadata.connection_token[-8:]):
            self._send(connection, ConnectionClose(reason="Invalid connection token timestamp."))
            return

        # Create a master key and kem-wrapped master key.
        kem_wrapped_key = QuantumKem.encapsulate(public_key=request.ephemeral_public_key)
        kem_signature = QuantumSign.sign(skey=self._this_static_secret_key, msg=kem_wrapped_key.encapsulated, id_=remote_session_id)
        connection.e2e_primary_keys[0] = kem_wrapped_key.decapsulated

        # Create a new request responding to the handshake request.
        self._send(connection, ConnectionAccept(
            certificate=self._this_certificate,
            kem_master_key=kem_wrapped_key.encapsulated,
            signature=kem_signature))

        # Clean up the connection object and mark it as open.
        del connection.that_ephemeral_public_key
        connection.connection_state = ConnectionState.ConnectionOpen

    def _handle_connection_accept(self, request: ConnectionAccept) -> None:
        # Get the connection object for this request.
        metadata = request.request_metadata
        connection = self._conversations[metadata.connection_token]
        local_session_id = connection.connection_token + self._this_identifier

        that_certificate = request.certificate
        that_public_key = that_certificate.tbs_certificate.subject_pk_info["public_key"]

        # Verify the certificate of the remote node.
        d_pkey = that_certificate.tbs_certificate.issuer_pk_info["public_key"]
        if not QuantumSign.verify(pkey=d_pkey, sig=that_certificate.signature_value, id_=metadata.that_identifier, tolerance=TOLERANCE_CERTIFICATE_SIGNATURE):
            self._send(connection, ConnectionClose(reason="Invalid certificate."))
            return
        self._cached_certificates[metadata.that_identifier] = that_certificate

        # Verify the signature of the ephemeral public key.
        if not QuantumSign.verify(pkey=that_public_key, sig=request.signature, id_=local_session_id):
            self._send(connection, ConnectionClose(reason="Invalid signature on kem wrapped key."))
            return
        self._cached_public_keys[metadata.that_identifier] = that_public_key

        # Unwrap the master key and store it in the connection object.
        kem_wrapped_key = QuantumKem.decapsulate(
            secret_key=connection.this_ephemeral_secret_key,
            encapsulated=request.kem_master_key)
        connection.e2e_primary_keys[0] = kem_wrapped_key.decapsulated

        # Clean up the connection object and mark it as open.
        del connection.this_ephemeral_secret_key
        del connection.this_ephemeral_public_key
        connection.connection_state = ConnectionState.ConnectionOpen

    def _handle_connection_close(self, request: ConnectionClose) -> None:
        # Get the connection object for this request.
        metadata = request.request_metadata
        connection = self._conversations[metadata.connection_token]
        self._logger.info(f"Connection closed: {request.reason}")

        # Clean up the connection object and mark it as closed.
        connection.connection_state = ConnectionState.ConnectionClosed
        del self._conversations[metadata.connection_token]

    def _handle_rotate_key(self, request: ConnectionRotateKey) -> None:
        # Get the connection object for this request.
        metadata = request.request_metadata
        connection = self._conversations[metadata.connection_token]

        # Check if the current key matches the hashed key.
        current_key = list(connection.e2e_primary_keys.values())[-1]
        current_key_hashed = Hasher.hash(data=current_key, algorithm=HashAlgorithm.SHA3_256())
        if current_key_hashed != request.cur_key_hashed:
            self._send(connection, ConnectionClose(reason="Invalid current key hash."))
            return

        # Unwrap the new key and store it in the connection object.
        new_key = SymmetricEncryption.unwrap_new_key(
            current_key=current_key,
            wrapped_key=request.new_key_wrapped)
        connection.e2e_primary_keys[request.after * 100] = new_key

        # Clean up the connection object and mark it as open.
        connection.key_rotations += 1
