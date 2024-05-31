import socket
from threading import Thread
import select


class Proxy:
    _connections = {}
    _server_socket: socket.socket

    def __init__(self):
        self._connections = {}
        self._server_socket = socket.socket()
        self._server_socket.bind(("localhost", 50000))
        self._server_socket.listen(20)

        Thread(target=self._run).start()

    def _run(self) -> None:
        while True:
            client_socket, addr = self._server_socket.accept()
            Thread(target=self._handle_client, args=(client_socket,)).start()

    def _unique_id(self) -> str:
        return str(len(self._connections) + 1)

    def _handle_client(self, client_socket: socket.socket) -> None:
        # Handle the CONNECT request
        data = client_socket.recv(1024)
        lines = data.split(b"\r\n")
        _, target_host, _ = lines[0].split(b" ")

        # Establish connection to the target host
        target_socket = socket.socket()
        target_socket.connect((target_host.split(b":")[0], int(target_host.split(b":")[1])))

        # Generate a unique id and store the connection
        unique_id = self._unique_id()
        self._connections[unique_id] = target_socket

        # Send a 200 OK response to the client
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Set the sockets to non-blocking mode
        client_socket.setblocking(False)
        target_socket.setblocking(False)

        # Handle data transfer between the client, and the target
        Thread(target=self._handle_data_transfer, args=(unique_id, client_socket, target_socket)).start()

    def _handle_data_transfer(self, unique_id: str, client_socket: socket.socket, target_socket: socket.socket) -> None:
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

    def __del__(self):
        self._server_socket.close()


def main():
    proxy = Proxy()
    input()


if __name__ == "__main__":
    main()
