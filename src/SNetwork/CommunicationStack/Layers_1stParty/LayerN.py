from __future__ import annotations

import pickle
from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from logging import Logger
from socket import socket as Socket
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Isolation import strict_isolation
from SNetwork.QuantumCrypto.Symmetric import SymmetricEncryption
from SNetwork.Utils.Types import Bytes, Int, Optional, Tuple, Bool, Type, Str

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.Managers.KeyManager import KeyStoreData


class ConnectionState(Enum):
    NotConnected = 0x00
    PendingConnection = 0x01
    ConnectionOpen = 0x02
    ConnectionClosed = 0x03


@dataclass(slots=True)
class Connection:
    """
    Each Connection object represents a connection to a remote node. It contains a list of data pertaining to the node,
    and the encrypted connection.

    Attributes:
        peer_ip: The IPv6 address of the remote node.
        peer_port: The port number of the remote node.
        peer_id: The identifier of the remote node.
        conn_tok: The unique connection identifier.
        conn_state: The current state of the connection.
        peer_ephemeral_pkey: The ephemeral public key of the remote node for this connection.
        e2e_primary_key: The end-to-end primary key.
    """

    peer_ip: IPv6Address
    peer_port: Int
    peer_id: Bytes
    conn_tok: Bytes
    conn_state: ConnectionState = field(default=ConnectionState.NotConnected)
    peer_ephemeral_pkey: Optional[Bytes] = field(default=b"")
    self_ephemeral_pkey: Optional[Bytes] = field(default=b"")
    self_ephemeral_skey: Optional[Bytes] = field(default=b"")
    e2e_primary_key: Optional[Bytes] = field(default=b"")
    message_no: Int = field(default=0, init=False)

    def is_accepted(self) -> Bool:
        return self.conn_state == ConnectionState.ConnectionOpen

    def is_rejected(self) -> Bool:
        return self.conn_state == ConnectionState.ConnectionClosed

    @property
    def socket_address(self) -> Tuple[Str, Int]:
        return self.peer_ip.exploded, self.peer_port


class LayerNProtocol(Enum):
    """
    A class implemented onto each protocol enumeration defined at each layer of the network stack.
    """


@dataclass(kw_only=True)
class AbstractRequest:
    def serialize(self) -> Bytes:
        # Serialize the fields, with "byte => .hex()" conversion.
        result = pickle.dumps(self)
        return result

    @staticmethod
    def deserialize[T: AbstractRequest](data: Bytes, to: Type[T] = None) -> T:
        # Deserialize the fields, with ".hex() => byte" conversion.
        result = pickle.loads(data)
        return result

    def __str__(self) -> str:
        return "\n".join([f"{key} = {value}" for key, value in self.__dict__.items()])


@dataclass(kw_only=True)
class RawRequest(AbstractRequest):
    meta: RequestMetadata = None
    secure: Bool = False


@dataclass(kw_only=True)
class EncryptedRequest(AbstractRequest):
    conn_tok: Bytes
    ciphertext: Bytes
    secure: Bool = True


@dataclass(kw_only=True)
class RequestMetadata:
    conn_tok: Bytes
    sender_id: Bytes
    stack_layer: Str
    proto: LayerNProtocol
    message_no: Int


class LayerN:
    """
    Abstract class, which defines the structure of a network layer. Every method in this class is abstract and must be
    implemented by a subclass. The purpose of this class is to define a common interface for network layers. Each layer
    operates over a separate socket, isolating subsets of commands and data from the rest of the stack.

    Attributes:
        _socket: The socket object used to send and receive data.
    """

    _stack: CommunicationStack
    _self_node_info: Optional[KeyStoreData]
    _proto: Type[LayerNProtocol]
    _socket: Socket
    _logger: Logger

    def __init__(self, stack: CommunicationStack, node_info: Optional[KeyStoreData], protocol: Type[LayerNProtocol], socket: Socket, logger: Logger):
        """
        The constructor for the LayerN class. This method creates a new socket object, which is used to send and receive
        data. The socket type is defined by the socket_type parameter, which defaults to SOCK_DGRAM. The only time UDP
        isn't used is for the Layer1 proxy socket, which listens for TCP connections, to proxy the data out.
        """
        super().__init__()

        # Initialize the layer's connection attributes.
        self._socket = socket
        self._self_node_info = node_info
        self._proto = protocol
        self._stack = stack
        self._logger = logger

    @abstractmethod
    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: RawRequest) -> None:
        """
        This method is used to call the correct handler methods depending on the command received. The command is
        extracted from the request, and the appropriate handler is called. There can be optional validation checks, such
        as ensuring that the request contains a command and token.
        """

    @strict_isolation
    def _send(self, conn: Connection, req: RawRequest) -> None:
        """
        This method is used to send data to a connection. The connection object contains the necessary information to
        send the data to the correct node. Different layers treat the data differently, for example, encrypting the data
        will require a {"token": ..., "enc_data": ...} format, where-as raw data will only require the data to be sent.
        """

        # Add the connection token, and send the unencrypted data to the address.
        req = self._prep_data(conn, req)
        serialized = req.serialize()

        self._logger.debug(
            f"-> Sending raw '{req.meta.proto}' ({len(serialized)}-byte) request to "
            f"{conn.peer_id.hex()}@{conn.peer_ip}:{conn.peer_port}")
        self._socket.sendto(serialized, conn.socket_address)

    @strict_isolation
    def _send_secure(self, conn: Connection, req: RawRequest) -> None:
        """
        This method is used to send secure data to a connection. The data is automatically marked as secure, allowing
        the single recv function to know whether decryption is necessary or not.
        """

        req = self._prep_data(conn, req)
        proto = req.meta.proto
        serialized = req.serialize()

        # Queue the request until the connection is accepted.
        while not conn.is_accepted():
            pass

        # Create the ciphertext using the correct primary key from the connection.
        ciphertext = SymmetricEncryption.encrypt(
            data=serialized,
            key=self._stack._layer4._conversations[conn.conn_tok].e2e_primary_key)

        # Form an encrypted request and send it to the address.
        serialized = EncryptedRequest(conn_tok=conn.conn_tok, ciphertext=ciphertext).serialize()

        self._logger.debug(f"-> Sending encrypted '{proto.name}' request to {conn.peer_id.hex()}")
        self._socket.sendto(serialized, conn.socket_address)

    def _prep_data(self, conn: Connection, req: RawRequest) -> RawRequest:
        """
        This method is used to prepare the data to be sent to a connection. The data has the connection stored under the
        "token" key, and a random message ID added to, for re-sending malformed messages. The data is then dumped to
        JSON, and converted to bytes and returned.
        """

        conn.message_no += 1
        req.meta = RequestMetadata(
            conn_tok=conn.conn_tok,
            sender_id=conn.peer_id,
            stack_layer=type(self).__name__[-1],
            proto=self._proto[type(req).__name__],
            message_no=conn.message_no)
        return req
