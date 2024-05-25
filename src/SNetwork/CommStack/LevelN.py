from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from ipaddress import IPv6Address
from socket import socket as Socket, AF_INET6, SOCK_DGRAM

from src.Utils.Types import Bytes, Json, Int, Optional
from src.Crypt.AsymmetricKeys import SecKey


@dataclass
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
        e2e_master_key: The end-to-end master key used to encrypt data between nodes.
    """

    address: IPv6Address
    identifier: Bytes
    token: Bytes
    state: LevelNProtocol
    challenge: Optional[Bytes]
    ephemeral_public_key: Optional[Bytes]
    ephemeral_secret_key: Optional[SecKey]
    e2e_master_key: Optional[Bytes]


class LevelNProtocol:
    """
    A class implemented onto each protocol enumeration defined at each layer of the network stack.
    """
    ...


class LevelN(ABC):
    """
    Abstract class that defines the structure of a network layer. Every method in this class is abstract and must be
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

    _socket: Socket

    def __init__(self):
        self._socket = Socket(AF_INET6, SOCK_DGRAM)

    @abstractmethod
    def _listen(self) -> None:
        ...

    @abstractmethod
    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        ...

    @abstractmethod
    def _send(self, connection: Connection, data: Json) -> None:
        ...

    @property
    @abstractmethod
    def _port(self) -> Int:
        ...

    def __del__(self):
        self._socket.close()
