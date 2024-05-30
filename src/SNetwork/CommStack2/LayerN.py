from __future__ import annotations

import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from ipaddress import IPv6Address
from socket import socket as Socket, AF_INET6, SOCK_DGRAM
from threading import Thread, Lock

from SNetwork.Crypt.AsymmetricKeys import PubKey, SecKey
from SNetwork.Utils.Types import Bytes, Json, Int, Optional, Dict, Float, Tuple
from SNetwork.Utils.Json import SafeJson
from SNetwork.Config import CONNECTION_TIMEOUT


@dataclass(kw_only=True)
class Connection:
    """
    Each Connection object represents a connection to a remote node. It contains a list of data pertaining to the node,
    and the encrypted connection.

    Attributes:
        address: The IPv6 address of the remote node.
        identifier: The identifier of the remote node.
        token: The unique connection identifier.
        state: The current state of the connection.
        challenge: The challenge sent by the remote node.
        ephemeral_public_key: The ephemeral public key used to establish a secure connection.
        ephemeral_secret_key: The ephemeral secret key used to establish a secure connection.
        e2e_primary_key: The end-to-end primary key other keys are derived from.
    """

    address: IPv6Address
    identifier: Bytes
    token: Bytes
    state: LayerNProtocol
    challenge: Optional[Bytes]
    ephemeral_public_key: Optional[PubKey]
    ephemeral_secret_key: Optional[SecKey]
    e2e_primary_key: Optional[Bytes]


class LayerNProtocol:
    """
    A class implemented onto each protocol enumeration defined at each layer of the network stack.
    """
    ...


class LayerN(ABC):
    """
    Abstract class, which defines the structure of a network layer. Every method in this class is abstract and must be
    implemented by a subclass. The purpose of this class is to define a common interface for network layers. Each layer
    operates over a separate socket, isolating subsets of commands and data from the rest of the stack.

    Attributes:
        _socket: The socket object used to send and receive data.
        _message_map: A dictionary used to store recently sent messages.

    Methods:
        _listen: The method that listens for incoming data.
        _handle_command: The method that processes incoming data.
        _send: The method that sends data to a connection.
        _port: The port number used by the layer.
    """

    _socket: Socket
    _message_map: Dict[Bytes, Tuple[Float, Json]]
    _message_map_lock: Lock

    def __init__(self, socket_type: Int = SOCK_DGRAM):
        """
        The constructor for the LayerN class. This method creates a new socket object, which is used to send and receive
        data. The socket type is defined by the socket_type parameter, which defaults to SOCK_DGRAM. The only time UDP
        isn't used is for the Layer1 proxy socket, which listens for TCP connections, to proxy the data out.
        """

        # Initialize the socket and message map.
        self._socket = Socket(AF_INET6, socket_type)
        self._message_map = {}
        self._message_map_lock = Lock()

        # Start the message map cleaner thread.
        Thread(target=self._clean_message_map).start()

    @abstractmethod
    def _listen(self) -> None:
        """
        This method is used to listen for incoming data on the socket. There is a "listen" method per port being used by
        the Communication Stack. This is because each layer of the stack interprets data differently; Layer4 will
        receive raw, unencrypted data, where-as Layer2/3 will receive encrypted data. Layer1 only receives data from the
        applications running the proxy.
        """

    @abstractmethod
    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        """
        This method is used to call the correct handler methods depending on the command received. The command is
        extracted from the request, and the appropriate handler is called. There can be optional validation checks, such
        as ensuring that the request contains a command and token.
        """

    @abstractmethod
    def _send(self, connection: Connection, data: Json) -> None:
        """
        This method is used to send data to a connection. The connection object contains the necessary information to
        send the data to the correct node. Different layers treat the data differently, for example, encrypting the data
        will require a {"token": ..., "enc_data": ...} format, where-as raw data will only require the data to be sent.
        """

    @property
    @abstractmethod
    def _port(self) -> Int:
        """
        This property is used to return the port number used by the layer. This is used to bind the socket to the
        correct port, and to identify the layer in the Communication Stack. It is defined as a property to allow
        abstract methods to use the port no matter the implementation.
        """

    def _prep_data(self, connection: Connection, data: Json) -> Bytes:
        """
        This method is used to prepare the data to be sent to a connection. The data has the connection stored under the
        "token" key, and a random message ID added to, for re-sending malformed messages. The data is then dumped to
        JSON, and converted to bytes and returned.
        """

        data["token"] = connection.token
        data["id"] = secrets.token_bytes(16)
        self._message_map[data["id"]] = (time.time(), data)
        return SafeJson.dumps(data)

    def _clean_message_map(self) -> None:
        """
        This method is used to clean the message map of old messages. The message map is a dictionary that stores the
        message ID and the time it was sent. If the message is older than the CONNECTION_TIMEOUT, it is removed from the
        dictionary.
        """

        while True:
            time.sleep(CONNECTION_TIMEOUT)
            with self._message_map_lock:
                timeout_check = lambda x: time.time() - x[0] < CONNECTION_TIMEOUT
                self._message_map = {k: v for k, v in self._message_map.items() if timeout_check(v)}

    def __del__(self):
        """
        The shared deletion method for all LayerN objects. This method closes the socket when the object is deleted, as
        long as the socket is not yet closed.
        """

        self._socket and self._socket.close()
