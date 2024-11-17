import secrets, select
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket, AF_INET, AF_INET6, SOCK_STREAM
from threading import Thread

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, LayerNProtocol, Connection
from SNetwork.CommunicationStack.Isolation import cross_isolation, strict_isolation
from SNetwork.Config import MAX_TCP_LISTEN, HTTP_CONNECT_ESTABLISHED, DEFAULT_IPV6
from SNetwork.Utils.Types import Bytes, Callable, Json, Int
from SNetwork.CommunicationStack.Layers_2ndParty.LayerHTTP.SelectableDict import SelectableDict, Selectable


class Layer1Protocol(LayerNProtocol, Enum):
    ...


class LayerHTTP(LayerN):
    """
    The "_socket" is the proxy socket, which receives incoming data from the client. The "_target_sockets" are the
    sockets that are maintained as an exit node that exchange data with the client.

    Attributes
        _incoming_dict: A dictionary for the client that holds responses from the route.
        _outgoing_dict: A dictionary for the exit node that holds requests from the client.
    """

    _incoming_dict: SelectableDict[Bytes]
    _outgoing_dict: SelectableDict[Bytes]

    def __init__(self, stack, port: Int) -> None:
        socket = Socket(family=SOCK_STREAM, type=AF_INET6)
        super().__init__(stack, socket)

        self._incoming_dict = SelectableDict[Bytes]()
        self._outgoing_dict = SelectableDict[Bytes]()

        # Listen for incoming connections.
        self._socket.bind((DEFAULT_IPV6, port))
        self._socket.listen(MAX_TCP_LISTEN)

        # Start listening on the socket for this layer.
        Thread(target=self._listen).start()
        logging.debug("Layer 1 Ready")

    @cross_isolation(2)
    def open_tcp_connection_for_client(self, request: Json) -> None:
        self._handle_target(request)
        
    @cross_isolation(2)
    def store_data_sent_to_the_internet(self, request: Json) -> None:
        socket_id = request["socket_id"]
        self._outgoing_dict[socket_id] = bytes.fromhex(request["data"])
        
    @cross_isolation(2)
    def store_data_recv_from_the_internet(self, request: Json) -> None:
        socket_id = request["socket_id"]
        self._incoming_dict[socket_id] = bytes.fromhex(request["data"])

    def _listen(self) -> None:
        # Listen on the proxy localhost socket (port 50000).
        while True:
            client_socket, _ = self._socket.accept()
            Thread(target=self._handle_client, args=(client_socket, )).start()

    @strict_isolation
    def _handle_target(self, request: Json) -> None:
        # Create the socket to the internet, and connect to the host.
        internet_socket = Socket(AF_INET if request["type"] == "ipv4" else AF_INET6, SOCK_STREAM)
        internet_socket.connect((request["host"], request["port"]))
        internet_socket.setblocking(False)
        socket_id = request["socket_id"]

        # Save the connection to the target socket.
        internet_recv_buffer = self._outgoing_dict[request["socket_id"]]

        # Set the sockets to non-blocking mode.
        internet_recv_buffer.setblocking(False)
        internet_socket.setblocking(False)

        # Handle data transfer between the client, and the target.
        tunnel_func = self._stack._layer2.tunnel_internet_response
        args = (socket_id, internet_socket, internet_recv_buffer, tunnel_func)
        Thread(target=self._handle_data_exchange, args=args).start()

    @strict_isolation
    def _handle_client(self, client_proxy_socket: Socket) -> None:
        # Receive the CONNECT request, and extract the host from the headers.
        data = client_proxy_socket.recv(1024)
        host = HttpParser(data).headers[b"Host"].decode()
        socket_id = secrets.token_bytes(16)

        # Get the unfilled Selectable and send a connection established response.
        route_recv_buffer = self._incoming_dict[socket_id]
        client_proxy_socket.sendall(HTTP_CONNECT_ESTABLISHED)
        self._stack._layer2.notify_exit_node_of_connection(host, socket_id)

        # Set the sockets to non-blocking mode.
        route_recv_buffer.setblocking(False)
        client_proxy_socket.setblocking(False)

        # Handle data transfer between the client, and the target.
        tunnel_func = self._stack._layer2.tunnel_internet_reqeust
        args = (socket_id, client_proxy_socket, route_recv_buffer, tunnel_func)
        Thread(target=self._handle_data_exchange, args=args).start()

    @strict_isolation
    def _handle_data_exchange(self, socket_id: Bytes, socket: Socket, buffer: Selectable[Bytes], tunnel_func: Callable[[Bytes, Bytes], None]) -> None:
        # Store the sockets in a list, for the selection.
        sockets = [socket, buffer]

        while True:
            # Get the readable and errored sockets.
            readable, _, errored = select.select(sockets, [], sockets)

            # Forward socket data into the route, and send dictionary-stored data to the client.
            for sock in readable:
                data = sock.recv(4096)
                if not data: break
                if sock is socket: tunnel_func(socket_id, data)
                if sock is buffer: socket.sendall(data)

            # Close the connection if an error occurs.
            for sock in errored:
                sockets.remove(sock)
                sock.close()

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        pass

    def _send(self, connection: Connection, protocol: LayerNProtocol, request: Json) -> None:
        pass
