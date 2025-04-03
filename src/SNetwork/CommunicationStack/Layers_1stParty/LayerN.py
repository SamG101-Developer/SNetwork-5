from __future__ import annotations

import pickle
from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from logging import Logger
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Isolation import strict_isolation
from SNetwork.QuantumCrypto.Symmetric import SymmetricEncryption
from SNetwork.Utils.Socket import Socket
from SNetwork.Utils.Types import Bytes, Int, Optional, Bool, Type

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
        peer_epk: The ephemeral public key of the remote node for this connection.
        e2e_key: The end-to-end primary key.
    """

    peer_ip: IPv6Address
    peer_port: Int
    peer_id: Bytes
    conn_tok: Bytes
    conn_state: ConnectionState = field(default=ConnectionState.NotConnected)
    peer_epk: Optional[Bytes] = field(default=b"")
    self_epk: Optional[Bytes] = field(default=b"")
    self_esk: Optional[Bytes] = field(default=b"")
    e2e_key: Optional[Bytes] = field(default=b"")

    def is_accepted(self) -> Bool:
        return self.conn_state == ConnectionState.ConnectionOpen

    def is_rejected(self) -> Bool:
        return self.conn_state == ConnectionState.ConnectionClosed


@dataclass(kw_only=True)
class AbstractRequest:
    def serialize(self) -> Bytes:
        # Serialize the fields.
        result = pickle.dumps(self)
        return result

    @staticmethod
    def deserialize[T: AbstractRequest](data: Bytes, to: Type[T] = None) -> T:
        # Deserialize the fields.
        result = pickle.loads(data)
        return result

    def __str__(self) -> str:
        return "\n".join([f"{key} = {value}" for key, value in self.__dict__.items()])


@dataclass(kw_only=True)
class RawRequest(AbstractRequest):
    conn_tok: Bytes = b""
    secure: Bool = False

    def __str__(self) -> str:
        return type(self).__name__


@dataclass(kw_only=True)
class EncryptedRequest(AbstractRequest):
    conn_tok: Bytes
    ciphertext: Bytes  # An encrypted serialized request
    secure: Bool = True


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
    _socket: Socket
    _logger: Logger

    def __init__(self, stack: CommunicationStack, node_info: Optional[KeyStoreData], socket: Socket, logger: Logger):
        """
        The constructor for the LayerN class. This method creates a new socket object, which is used to send and receive
        data. The socket type is defined by the socket_type parameter, which defaults to SOCK_DGRAM. The only time UDP
        isn't used is for the Layer1 proxy socket, which listens for TCP connections, to proxy the data out.
        """
        super().__init__()

        # Initialize the layer's connection attributes.
        self._socket = socket
        self._self_node_info = node_info
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
        self.attach_metadata(conn, req)
        serialized = req.serialize()

        self._logger.debug(
            f"-> Sending raw '{req}' ({len(serialized)}-byte) request to "
            f"{conn.peer_id.hex()}@{conn.peer_ip}:{conn.peer_port}")
        self._socket.sendto(serialized, conn.peer_ip, conn.peer_port)

    @strict_isolation
    def _send_secure(self, conn: Connection, req: RawRequest) -> None:
        """
        This method is used to send secure data to a connection. The data is automatically marked as secure, allowing
        the single recv function to know whether decryption is necessary or not.
        """

        self.attach_metadata(conn, req)
        serialized = req.serialize()

        # Queue the request until the connection is accepted.
        while not conn.is_accepted():
            pass

        # Create the ciphertext using the correct primary key from the connection.
        ciphertext = SymmetricEncryption.encrypt(
            data=serialized,
            key=self._stack._layer4._conversations[conn.conn_tok].e2e_key)

        # Form an encrypted request and send it to the address.
        serialized = EncryptedRequest(conn_tok=conn.conn_tok, ciphertext=ciphertext).serialize()

        self._logger.debug(f"-> Sending encrypted request to {conn.peer_id.hex()}")
        self._socket.sendto(serialized, conn.peer_ip, conn.peer_port)

    def attach_metadata(self, conn: Connection, req: RawRequest) -> None:
        req.conn_tok = conn.conn_tok
