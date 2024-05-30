import select
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket, SOCK_STREAM
from threading import Thread

from SNetwork.Config import LAYER_1_PORT
from SNetwork.CommStack2.LayerN import LayerN, LayerNProtocol, Connection
from SNetwork.CommStack2.Layer2 import Layer2
from SNetwork.Utils.Types import Int, Json
from SNetwork.Utils.HttpParser import HttpParser
from SNetwork.Utils.SelectableDict import SelectableDict, Selectable


class Layer1Protocol(LayerNProtocol, Enum):
    ...


class Layer1(LayerN):
    _layer2: Layer2
    _selectable_dict: SelectableDict[Int, Json]

    def __init__(self, layer2: Layer2):
        super().__init__(SOCK_STREAM)

        self._layer2 = layer2
        self._selectable_dict = SelectableDict[Int, Json]()

    def _listen(self) -> None:
        while True:
            client_socket, _ = self._socket.accept()
            Thread(target=self._handle_client, args=(client_socket, )).start()

    def _handle_client(self, client_socket: Socket) -> None:
        # Receive the CONNECT request, and extract the host.
        data = client_socket.recv(1024)
        host = HttpParser(data).headers[b"Host"].decode()

        # Get the target key from the dictionary.
        unique_id = len(self._selectable_dict) + 1
        # todo: forward message to entry node with "unique_id" attached [layer 2]

        # Get the unfilled Selectable and send a connection established response.
        target_getter = self._selectable_dict[unique_id]
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Set the sockets to non-blocking mode.
        target_getter.setblocking(False)
        client_socket.setblocking(False)

        # Handle data transfer between the client, and the target.
        Thread(target=self._handle_data_transfer, args=(unique_id, client_socket, target_getter)).start()

    def _handle_data_transfer(self, unique_id: Int, client_socket: Socket, target_getter: Selectable[Int]) -> None:
        try:
            # Store the sockets in a list, for the selection.
            sockets = [client_socket, target_getter]
            while True:

                # Get the readable and errored sockets.
                readable, _, errored = select.select(sockets, [], sockets)

                # Receive data from the readable sockets, and send it to the other socket.
                for sock in readable:
                    data = sock.recv(4096)
                    if not data:
                        break
                    if sock is client_socket:
                        target_getter.set_value(data)
                    else:
                        client_socket.sendall(data)

                # Remove and close any errored sockets (prevents trying to read from a closed socket).
                for sock in errored:
                    sockets.remove(sock)
                    sock.close()

        except ConnectionResetError:
            # If there is an error, close the sockets and exit the thread. This would be done anyway, so the code is in
            # the "finally" block.
            ...

        finally:
            # Close the sockets.
            client_socket.close()
            target_getter.close()

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        pass

    def _send(self, connection: Connection, data: Json) -> None:
        pass

    @property
    def _port(self) -> Int:
        return LAYER_1_PORT
