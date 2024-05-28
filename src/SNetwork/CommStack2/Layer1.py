from ipaddress import IPv6Address
from socket import socket as RawSocket, SOCK_STREAM
from threading import Thread

from SNetwork.CommStack2.LayerN import LayerN, LayerNProtocol, Connection
from SNetwork.Config import LAYER_0_PORT, LOOPBACK_IPV6
from SNetwork.Utils.Types import Int, Json, Dict, Str


class Layer1Protocol(LayerNProtocol):
    InitConnection = 0
    ConnectionEstablished = 1


class SelectableDict[K, V]:
    """
    The SelectableDict wraps a dictionary class with an IO-like access to get values associated with possibly existing
    keys. In the same way that socket.recv() will wait until data is available, this class will wait until a key is
    available in the dictionary. This allows it to be used in "select.select()" calls, with other buffers like sockets.
    """

    _dict: Dict[K, V]

    def __init__(self):
        self._dict = {}

    def __getitem__(self, key: K) -> V:
        while key not in self._dict:
            pass
        return self._dict[key]

    def __setitem__(self, key: K, value: V) -> None:
        self._dict[key] = value

    def __delitem__(self, key: K) -> None:
        del self._dict[key]

    def __contains__(self, key: K) -> bool:
        return key in self._dict

    def __len__(self) -> Int:
        return len(self._dict)


class Layer1(LayerN):
    _socket_map: SelectableDict[Int, RawSocket]

    def __init__(self):
        # The Layer0 socket must be a TCP socket, as it is used to intercept messages as a proxy for HTTPS connections.
        super().__init__(SOCK_STREAM)

    def _listen(self) -> None:
        # The local interceptor socket is used to intercept messages as a proxy. It operates on a different port to
        # standard Layer1 data transfer, to separate data from other routes that use this node as a route node.
        self._socket.bind((LOOPBACK_IPV6, LAYER_0_PORT))
        self._socket.listen(20)

        #
        while True:
            client_socket, address = self._socket.accept()
            Thread(target=self._handle_command, args=(address, client_socket)).start()

    def _unique_id(self) -> Int:
        return len(self._socket_map) + 1

    def _handle_command(self, address: IPv6Address, client_socket: RawSocket) -> None:
        # Handle the CONNECT request from the client.
        data = client_socket.recv(1024)
        lines = data.split(b"\r\n")
        _, target_host, _ = lines[0].split(b" ")

        # Send a 200 OK response to the client
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        client_socket.setblocking(False)

        # Handle data transfer between the client, and the target
        Thread(target=self._manage_data_transfer, args=(client_socket, target_host)).start()

    def _send(self, connection: Connection, data: Json) -> None:
        pass

    @property
    def _port(self) -> Int:
        return LAYER_0_PORT

    def _manage_data_transfer(self, client_socket: RawSocket, target_host: Str) -> None:
        try:
            sockets = [client_socket, target_socket]
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets)
                for sock in readable:
                    data = sock.recv(4096)
                    if not data: break
                    if sock is client_socket:
                        print(f"Data received from client [{client_socket.getpeername()[0]}]: {data}")
                        target_socket.sendall(data)
                    else:
                        print(f"Data received from target [{target_socket.getpeername()[0]}]: {data}")
                        client_socket.sendall(data)

                for sock in exceptional:
                    sockets.remove(sock)
                    sock.close()

        except ConnectionResetError:
            print("Connection reset by client")

        finally:
            client_socket.close()
            target_socket.close()
