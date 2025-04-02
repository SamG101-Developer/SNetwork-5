from __future__ import annotations

from ipaddress import IPv6Address
from socket import socket as RawSocket, SOL_SOCKET, SO_REUSEADDR, AF_INET6, SOCK_DGRAM
from typing import TYPE_CHECKING
from threading import Lock

if TYPE_CHECKING:
    from SNetwork.Utils.Types import Int, Optional


class Socket:
    """
    Socket class for the SNetwork library. This class is used to create and manage sockets for communication between
    nodes. It is a wrapper around the standard socket library, and provides additional functionality for the SNetwork
    library.

    This socket is UDP only, and is used for all communication between nodes. It is created with the IPv6 address family,
    and the datagram socket type. The socket is set to reuse the address. Most importantly, it is thread-safe, and can
    be used in a multithreaded environment.

    Attributes:
        _mutex: A mutex used to synchronize access to the socket.
        _socket: The socket object used to send and receive data.
    """

    _mutex: Lock
    _socket: Optional[RawSocket]

    def __init__(self) -> None:
        self._mutex = Lock()
        self._init_socket()

    def _init_socket(self) -> None:
        """
        Initialize the socket. This is used to create the socket object and set the options for the socket.
        """

        self._socket = RawSocket(family=AF_INET6, type=SOCK_DGRAM)
        self._socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    def bind(self, port: Int) -> None:
        """
        Bind the socket to the specified port. This is used to listen for incoming connections.

        Args:
            port: The port number to bind the socket to.
        """

        self._socket.bind(("::", port))

    def close(self) -> None:
        """
        Close the socket. This is used to release the resources used by the socket.
        """

        self._socket.close()
        self._socket = None

    def sendto(self, data: bytes, ip: IPv6Address, port: Int) -> None:
        """
        Send data to the specified address. This is used to send data to other nodes in the network.

        Args:
            data: The data to send.
            ip: The IP address of the destination node.
            port: The port number of the destination node.
        """

        print(f"Sending data to {ip.exploded}:{port}")
        self._socket.sendto(data, (ip.exploded, port))

    def recvfrom(self, buffer_size: Int) -> tuple[bytes, IPv6Address, Int]:
        """
        Receive data from the socket. This is used to receive data from other nodes in the network.

        Args:
            buffer_size: The maximum size of the data to receive.
        """

        data, address = self._socket.recvfrom(buffer_size)
        return data, IPv6Address(address[0]), address[1]

    def __del__(self) -> None:
        """
        Close the socket when the object is deleted. This is used to release the resources used by the socket.
        """

        self._socket and self._socket.close()
