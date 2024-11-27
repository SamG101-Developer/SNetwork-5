from __future__ import annotations
from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from logging import Logger
from socket import socket as Socket
from typing import TYPE_CHECKING
import pickle

from SNetwork.CommunicationStack.Isolation import strict_isolation
from SNetwork.QuantumCrypto.Symmetric import SymmetricEncryption
from SNetwork.Utils.Types import Bytes, Callable, Dict, Json, Int, Optional, Tuple, Bool, Type, Str

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
        that_address: The IPv6 address of the remote node.
        that_port: The port number of the remote node.
        that_identifier: The identifier of the remote node.
        connection_token: The unique connection identifier.
        connection_state: The current state of the connection.
        that_ephemeral_public_key: The ephemeral public key of the remote node for this connection.
        e2e_primary_keys: The end-to-end primary keys other keys are derived from: {0: ..., 100: ...} for rotations.
    """

    that_address: IPv6Address
    that_port: Int
    that_identifier: Bytes
    connection_token: Bytes
    connection_state: ConnectionState = field(default=ConnectionState.NotConnected)
    that_ephemeral_public_key: Optional[Bytes] = field(default=b"")
    this_ephemeral_public_key: Optional[Bytes] = field(default=b"")
    this_ephemeral_secret_key: Optional[Bytes] = field(default=b"")
    e2e_primary_keys: Optional[Dict[Int, Bytes]] = field(default_factory=dict)
    socket_error_handler: Callable = field(default_factory=dict)
    key_rotations: Int = field(default=0, init=False)
    message_sent_number: Int = field(default=0, init=False)

    def is_accepted(self) -> Bool:
        return self.connection_state == ConnectionState.ConnectionOpen

    def is_rejected(self) -> Bool:
        return self.connection_state == ConnectionState.ConnectionClosed

    @property
    def socket_address(self) -> Tuple[Str, Int]:
        return self.that_address.exploded, self.that_port


class LayerNProtocol(Enum):
    """
    A class implemented onto each protocol enumeration defined at each layer of the network stack.
    """
    ...


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


class RawRequest(AbstractRequest):
    request_metadata: RequestMetadata
    secure: Bool = False


@dataclass(kw_only=True)
class EncryptedRequest(AbstractRequest):
    connection_token: Bytes
    encrypted_data: Bytes
    secure: Bool = True


@dataclass(kw_only=True)
class RequestMetadata:
    connection_token: Bytes
    that_identifier: Bytes
    stack_layer: Str
    protocol: LayerNProtocol
    message_number: Int


class LayerN:
    """
    Abstract class, which defines the structure of a network layer. Every method in this class is abstract and must be
    implemented by a subclass. The purpose of this class is to define a common interface for network layers. Each layer
    operates over a separate socket, isolating subsets of commands and data from the rest of the stack.

    Attributes:
        _socket: The socket object used to send and receive data.

    Methods:
        _listen: The method that listens for incoming data.
        _handle_command: The method that processes incoming data.
        _send: The method that sends data to a connection.
        _port: The port number used by the layer.
    """

    _stack: CommunicationStack
    _node_info: Optional[KeyStoreData]
    _protocol: Type[LayerNProtocol]
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
        self._node_info = node_info
        self._protocol = protocol
        self._stack = stack
        self._logger = logger

    @abstractmethod
    def _handle_command(self, address: IPv6Address, port: Int, data: RawRequest) -> None:
        """
        This method is used to call the correct handler methods depending on the command received. The command is
        extracted from the request, and the appropriate handler is called. There can be optional validation checks, such
        as ensuring that the request contains a command and token.
        """

    @strict_isolation
    def _send(self, connection: Connection, request: RawRequest) -> None:
        """
        This method is used to send data to a connection. The connection object contains the necessary information to
        send the data to the correct node. Different layers treat the data differently, for example, encrypting the data
        will require a {"token": ..., "enc_data": ...} format, where-as raw data will only require the data to be sent.
        """

        # Add the connection token, and send the unencrypted data to the address.
        encoded_data = self._prep_data(connection, request).serialize()
        protocol = request.request_metadata.protocol
        self._logger.debug(f"-> Sending raw '{protocol}' ({len(encoded_data)}-byte) request to {connection.that_identifier.hex()}")
        self._socket.sendto(encoded_data, connection.socket_address)

    @strict_isolation
    def _send_secure(self, connection: Connection, request: RawRequest) -> None:
        """
        This method is used to send secure data to a connection. The data is automatically marked as secure, allowing
        the single recv function to know whether decryption is necessary or not.
        """

        request = self._prep_data(connection, request)
        protocol = request.request_metadata.protocol

        # Create the ciphertext using the correct primary key from the connection.
        encrypted_data = SymmetricEncryption.encrypt(
            data=request.serialize(),
            key=self._stack._layer4._conversations[connection.connection_token].e2e_primary_keys[request.request_metadata.message_number // 100])

        # Form an encrypted request and send it to the address.
        secure_request = EncryptedRequest(
            connection_token=connection.connection_token,
            encrypted_data=encrypted_data)
        encoded_data = secure_request.serialize()

        self._logger.debug(f"-> Sending encrypted '{protocol.name}' request to {connection.that_identifier.hex()}")
        self._socket.sendto(encoded_data, (connection.that_address.exploded, connection.that_port))

    def _prep_data(self, connection: Connection, request: RawRequest) -> RawRequest:
        """
        This method is used to prepare the data to be sent to a connection. The data has the connection stored under the
        "token" key, and a random message ID added to, for re-sending malformed messages. The data is then dumped to
        JSON, and converted to bytes and returned.
        """

        connection.message_sent_number += 1
        request.request_metadata = RequestMetadata(
            connection_token=connection.connection_token,
            that_identifier=connection.that_identifier,
            stack_layer=type(self).__name__[-1],
            protocol=self._protocol[type(request).__name__],
            message_number=connection.message_sent_number)
        return request
