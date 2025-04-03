from __future__ import annotations

import socket
from dataclasses import dataclass
from ipaddress import IPv6Address
from threading import Thread, Lock
from typing import TYPE_CHECKING

import select

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import RawRequest, EncryptedRequest
from SNetwork.CommunicationStack.Layers_2ndParty.Layer1_Abstract import Layer1_Abstract
from SNetwork.Utils.Types import Int, Optional

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack


HTTP_OK = b"HTTP/1.1 200 Connection Established\r\n\r\n"


class SelectableBytesIO:
    """
    A subclass of BytesIO that can be used with select.select. This allows the BytesIO object to be used as a
    socket-like object, which can be used for reading and writing data.
    """

    _notif_sock: socket.socket
    _write_sock: socket.socket

    def __init__(self) -> None:
        super().__init__()
        self._notif_sock, self._write_sock = socket.socketpair()

    def fileno(self) -> int:
        return self._notif_sock.fileno()

    def write(self, buffer, /) -> None:
        self._write_sock.send(buffer)

    def recv(self, size: int = -1) -> bytes:
        return self._notif_sock.recv(size)

    def close(self) -> None:
        self._notif_sock.close()
        self._write_sock.close()


class HttpParser:
    _http: bytes

    def __init__(self, http: bytes) -> None:
        self._http = http

    @property
    def method(self) -> bytes:
        return self._http.split(b" ")[0]

    @property
    def response_code(self) -> int:
        return int(self._http.split(b" ")[1].decode())

    @property
    def headers(self) -> dict[bytes, bytes]:
        headers = {}
        for line in self._http.split(b"\r\n")[1:]:
            if b": " not in line: continue
            key, value = line.split(b": ")
            headers[key] = value
        return headers


class Layer1_Http(Layer1_Abstract):
    """
    LayerHTTP is an application layer for HTTP communication. It maintains a TCP socket that acts as a proxy for chosen
    web applications, and sends the requests through the Layer2 routing layer. The exit node will communicate with the
    web server, and send the response back to the client through the route.
    """

    _proxy_socket: socket.socket
    _received_data_at_client: dict[int, SelectableBytesIO]
    _received_data_at_server: dict[int, SelectableBytesIO]
    _mutex: Lock

    @dataclass(kw_only=True)
    class HttpConnectToServer(RawRequest):
        client_sock_id: int
        host: str

    @dataclass(kw_only=True)
    class HttpDataToServer(RawRequest):
        client_sock_id: int
        data: bytes

    @dataclass(kw_only=True)
    class HttpDataToClient(RawRequest):
        client_sock_id: int
        data: bytes

    def __init__(self, stack: CommunicationStack, enable_proxy: bool = False) -> None:
        super().__init__(stack)

        # Initialize the attributes for the HTTP layer.
        self._received_data_at_client = {}
        self._received_data_at_server = {}
        self._mutex = Lock()

        # Create the TCP socket for the proxy.
        if enable_proxy:
            self._proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._proxy_socket.bind(("127.0.0.1", 9090))
            self._proxy_socket.listen(5)
            Thread(target=self._start, daemon=True).start()

    def _start(self):
        """
        Continuously listen for incoming connections on the proxy socket. When a connection is made, handle the request.
        This method is run in a separate thread to allow for multiple connections to be handled simultaneously.
        """

        while True:
            client_socket, _ = self._proxy_socket.accept()
            Thread(target=self._handle_proxy_request, args=(client_socket,), daemon=True).start()

    def _handle_proxy_request(self, client_socket: socket.socket) -> None:
        """
        To handle a proxy request, it needs to be routed through the route established by the Layer2 routing layer. The
        first command will always be a Http CONNECT request, so this has a special Layer1_Http request object.

        """

        # Get the CONNECT request from the client using the proxy.
        http_initial_request = client_socket.recv(1024)

        # Determine the host from the HTTP headers (example: "google.com").
        host_header = HttpParser(http_initial_request).headers.get(b"Host")
        if host_header is None:
            client_socket.close()
            return
        host = host_header.decode().split(":")[0].strip()

        # Create the CONNECT request object and send it through the route.
        client_socket_id = client_socket.fileno()
        http_connect_request = Layer1_Http.HttpConnectToServer(client_sock_id=client_socket_id, host=host)
        self._stack._layer1.tunnel_application_data_forwards(Layer1_Http, http_connect_request)

        # Create the response selectable-object that is interacted with from Layer1.
        self._received_data_at_client[client_socket_id] = routing_entry_point = SelectableBytesIO()
        client_socket.sendall(HTTP_OK)

        # Start data exchange between the client and routing entry point.
        self._handle_data_exchange_as_client(client_socket, routing_entry_point, client_socket_id)

    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: RawRequest, tun_req: Optional[RawRequest] = None) -> None:
        """
        Handle a command from Layer1. This method is used to call the correct handler methods depending on the command
        received. The command and sublayer (HTTP, FTP, etc), is determined from the request. The appropriate handler is
        called based on the command.
        """

        # Match the command to the appropriate handler.
        match req:

            # Handle a request to connect to a web server.
            case Layer1_Http.HttpConnectToServer():
                thread = Thread(target=self._handle_http_connect_to_server, args=(peer_ip, peer_port, req, tun_req))
                thread.start()

            # Handle a request to send http data to a web server.
            case Layer1_Http.HttpDataToServer():
                thread = Thread(target=self._handle_http_data_to_server, args=(peer_ip, peer_port, req, tun_req))
                thread.start()

            # Handle a request to send http data to a client.
            case Layer1_Http.HttpDataToClient():
                thread = Thread(target=self._handle_http_data_to_client, args=(peer_ip, peer_port, req))
                thread.start()

            # Handle either an invalid command from a connected token.
            case _:
                self._stack._layer1._logger.warning(f"Received invalid '{req}' request from '{req.conn_tok}'.")

    def _handle_http_connect_to_server(self, peer_ip: IPv6Address, peer_port: Int, req: Layer1_Http.HttpConnectToServer, tun_req: EncryptedRequest) -> None:
        """
        An exit node will receive a request to connect to a web server. This method will create a socket to the web
        server. This socket will communicate with the web server on behalf of the client, and will send all data back
        through the route.
        """

        self._stack._layer1._logger.info(f"Handling HTTP CONNECT request to server {req.host}")

        # Create a connection to the web server over secure HTTP port 443.
        internet_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        internet_socket.connect((req.host, 443))

        # Save the connection against the client socket identifier.
        self._received_data_at_server[req.client_sock_id] = routing_exit_point = SelectableBytesIO()
        self._handle_data_exchange_as_server(internet_socket, routing_exit_point, req.client_sock_id, tun_req.conn_tok)

    def _handle_http_data_to_server(self, peer_ip: IPv6Address, peer_port: Int, req: Layer1_Http.HttpDataToServer, tun_req: EncryptedRequest) -> None:
        """
        Send data that the client has sent through the route, to the web server. The correct web server socket is
        determined based on the client socket identifier.
        """

        self._stack._layer1._logger.info(f"Handling HTTP data to server")
        while req.client_sock_id not in self._received_data_at_server: pass

        # Write the data to the correct buffer, that will be sent to the web server.
        self._stack._layer1._logger.info(f"Client ID exists => writing {len(req.data)} route exit buffer.")
        self._received_data_at_server[req.client_sock_id].write(req.data)

    def _handle_http_data_to_client(self, peer_ip: IPv6Address, peer_port: Int, req: Layer1_Http.HttpDataToClient) -> None:
        """
        Send data that the web server has sent through the route, to the client. The correct client socket is determined
        based on the client socket identifier.
        """

        # Write data to the correct buffer, that will be sent to the client socket.
        self._stack._layer1._logger.info(f"Handling HTTP data to client")
        self._received_data_at_client[req.client_sock_id].write(req.data)

    def _handle_data_exchange_as_client(self, client_socket: socket.socket, routing_entry: SelectableBytesIO, client_sock_id: int) -> None:
        """
        The continuous data exchange between the client socket, and the routing entry point. This method will forward
        data on the client socket into the routing entry point; and data received through the route to the entry point,
        to the client socket.
        """

        # Create a socket pair to communicate with the routing entry point.
        sockets = [client_socket, routing_entry]
        readable, errored = [], []

        while True:

            # Get the readable and errored sockets.
            readable, _, errored = select.select(sockets, [], sockets, 1.0)
            if errored: break

            # Forward data from readable sockets into the opposite socket.
            for sock in readable:

                # Receive the data from either of the sockets.
                try:
                    data = sock.recv(16384)
                except ConnectionResetError:
                    errored.append(sock)
                    break

                if data is None: break
                if not data: continue

                # Determine the opposite socket.
                if sock is client_socket:
                    # Send the data to the communication stack.
                    request = Layer1_Http.HttpDataToServer(client_sock_id=client_sock_id, data=data)
                    self._stack._layer1.tunnel_application_data_forwards(Layer1_Http, request)
                    self._stack._layer1._logger.info(f"Sent HTTP data ({len(data)} bytes)  from client socket to routing entry point.")

                else:
                    # Write the raw HTTP response back to the client socket.
                    client_socket.sendall(data)
                    self._stack._layer1._logger.info(f"Sent HTTP data ({len(data)} bytes)  from routing entry point to client socket.")

        # Close the sockets.
        client_socket.close()
        routing_entry.close()

    def _handle_data_exchange_as_server(self, server_socket: socket.socket, routing_exit: SelectableBytesIO, client_sock_id: int, prev_conn_tok: bytes) -> None:
        """
        The continuous data exchange between the server socker, and the routing exit point. This method will forward
        data on the server socket into the routing exit point; and data received through the route to the exit point,
        to the server socket.
        """

        # Create a socket pair to communicate with the routing exit point.
        sockets = [server_socket, routing_exit]
        readable, errored = [], []

        while True:

            # Get the readable and errored sockets.
            readable, _, errored = select.select(sockets, [], sockets, 1.0)
            if errored: break

            # Forward data from readable sockets into the opposite socket.
            for sock in readable:

                # Receive the data from either of the sockets.
                try:
                    data = sock.recv(16384)
                except ConnectionResetError:
                    errored.append(sock)
                    break

                if data is None: break
                if not data: continue

                # Determine the opposite socket.
                if sock is server_socket:
                    # Send the data to the communication stack.
                    request = Layer1_Http.HttpDataToClient(client_sock_id=client_sock_id, data=data)
                    prev_conn = self._stack._layer4._conversations[prev_conn_tok]
                    self._stack._layer1.tunnel_application_data_backwards(Layer1_Http, prev_conn, request)
                    self._stack._layer1._logger.info(f"Sent HTTP data ({len(data)} bytes) from server socket to client's routing exit.")

                else:
                    # Write the raw HTTP response to the server socket.
                    server_socket.sendall(data)
                    self._stack._layer1._logger.info(f"Sent HTTP data ({len(data)} bytes) from client's routing exit to server socket.")

        # Close the sockets.
        server_socket.close()
        routing_exit.close()
        self._received_data_at_server.pop(client_sock_id, None)
        self._received_data_at_client.pop(client_sock_id, None)

        self._stack._layer1._logger.info(f"Closed HTTP connection for client socket {client_sock_id}.")

    def __del__(self) -> None:
        for sock in self._received_data_at_client.values(): sock.close()
        for sock in self._received_data_at_server.values(): sock.close()
        self._proxy_socket.close()
