from ipaddress import IPv4Address
from threading import Thread
import asyncio, json, logging, random

from src.kademlia.kademlia.network import Server
from src.CommStack.LevelN import LevelN
from src.CommStack.LevelD import LevelDProtocol
from src.Utils.Types import Json, Int, List
from src.CONFIG import LEVEL_D_PORT


class DirectoryService(LevelN):
    _cache: List[IPv4Address]
    _log: logging.Logger
    _loop: asyncio.AbstractEventLoop
    _dht_server: Server

    def __init__(self) -> None:
        super().__init__()
        self._cache = []
        logging.debug("Launching directory service")
        Thread(target=self._listen).start()
        Thread(target=self._host_dht).start()

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
                logging.debug(f"Handling leave network request from {address}")
                self._cache.remove(address)

    def _send(self, address: IPv4Address, data: Json) -> None:
        encoded_data = json.dumps(data).encode()
        self._socket.sendto(encoded_data, (address.exploded, self._port))

    def _handle_join_network(self, address: IPv4Address, request: Json) -> None:
        # Generate subset of random ids that should be online.
        logging.debug(f"Handling join network request from {address}")
        cache = self._cache.copy()
        cache = [c for c in cache if c.packed != address.packed]

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

    def _host_dht(self) -> None:
        self._loop = asyncio.get_event_loop()
        self._loop.set_debug(True)
        self._dht_server = Server()
        self._loop.run_until_complete(self._dht_server.listen(LEVEL_D_PORT))

        try:
            self._loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._dht_server.stop()
            self._loop.close()

    def __del__(self):
        self._dht_server.stop()
        self._loop.close()
