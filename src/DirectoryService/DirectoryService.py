import random
from ipaddress import IPv6Address
from socket import socket as Socket, AF_INET6, SOCK_DGRAM
from threading import Thread
import json

from src.CommStack.LevelN import LevelN
from src.CommStack.LevelD import LevelDProtocol
from src.Utils.Types import Json, Int, List
from src.CONFIG import LEVEL_D_PORT


class DirectoryService(LevelN):
    _socket: Socket
    _cache: List[IPv6Address]

    def __init__(self) -> None:
        self._socket = Socket(AF_INET6, SOCK_DGRAM)
        self._listen()

    def _listen(self) -> None:
        self._socket.bind(("::", self._port))
        while True:
            data, address = self._socket.recvfrom(1024)
            request = json.loads(data)
            Thread(target=self._handle_command, args=(IPv6Address(address[0]), request)).start()

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        if "command" not in request:
            return

        # Match the command to the appropriate handler.
        match request["command"]:
            case LevelDProtocol.JoinNetwork.value:
                self._handle_join_network(address, request)

    def _send(self, address: IPv6Address, data: Json) -> None:
        encoded_data = json.dumps(data).encode()
        self._socket.sendto(encoded_data, (address.exploded, self._port))

    def _handle_join_network(self, address: IPv6Address, request: Json) -> None:
        # Generate subset of random ids that should be online
        # Todo: sign this
        ip_address_subset = random.choices(self._cache, k=3)
        ip_address_subset = [ip.packed.hex() for ip in ip_address_subset]
        self._cache.append(address)

        # Send response
        response = {
            "command": LevelDProtocol.Bootstrap.value,
            "ips": ip_address_subset
        }
        self._send(address, response)

    @property
    def _port(self) -> Int:
        return LEVEL_D_PORT
