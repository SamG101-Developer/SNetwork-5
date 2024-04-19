from ipaddress import IPv4Address
from threading import Thread
import json, logging, random

from src.CommStack.LevelN import LevelN
from src.CommStack.LevelD import LevelDProtocol
from src.Utils.Types import Json, Int, List
from src.CONFIG import LEVEL_D_PORT


class DirectoryService(LevelN):
    _cache: List[IPv4Address]

    def __init__(self) -> None:
        super().__init__()
        self._cache = []
        logging.debug("Launching directory service")
        Thread(target=self._listen).start()

    def _listen(self) -> None:
        self._socket.bind(("", self._port))
        while True:
            data, address = self._socket.recvfrom(1024)
            request = json.loads(data)
            Thread(target=self._handle_command, args=(IPv4Address(address[0]), request)).start()

    def _handle_command(self, address: IPv4Address, request: Json) -> None:
        if "command" not in request:
            return

        # Match the command to the appropriate handler.
        match request["command"]:
            case LevelDProtocol.JoinNetwork.value:
                self._handle_join_network(address, request)
            case 14:
                self._cache.remove(address)

    def _send(self, address: IPv4Address, data: Json) -> None:
        encoded_data = json.dumps(data).encode()
        self._socket.sendto(encoded_data, (address.exploded, self._port))

    def _handle_join_network(self, address: IPv4Address, request: Json) -> None:
        # Generate subset of random ids that should be online.
        logging.debug(f"Handling join network request from {address}")
        cache = self._cache.copy()
        while address in cache:
            cache.remove(address)

        ip_address_subset = random.sample(self._cache, k=min(3, len(self._cache)))
        ip_address_subset = [ip.packed.hex() for ip in ip_address_subset]
        self._cache.append(address)

        # Send response
        response = {
            "command": LevelDProtocol.Bootstrap.value,
            "ips": ip_address_subset
        }

        # Todo: sign this
        self._send(address, response)

    @property
    def _port(self) -> Int:
        return LEVEL_D_PORT
