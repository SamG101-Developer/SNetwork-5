from ipaddress import IPv4Address
from threading import Thread
import asyncio, json, logging, random

from src.kademlia.network import Server
from src.CommStack.LevelN import LevelN
from src.CommStack.LevelD import LevelDProtocol
from src.Utils.Types import Json, Int, Dict
from src.CONFIG import LEVEL_D_PORT, LEVEL_0_PORT


class DirectoryService(LevelN):
    _cache: Dict[IPv4Address, Int]
    _log: logging.Logger
    _loop: asyncio.AbstractEventLoop
    _dht_server: Server

    def __init__(self) -> None:
        super().__init__()
        self._cache = {}
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
                self._cache.pop(address)

    def _send(self, address: IPv4Address, data: Json) -> None:
        encoded_data = json.dumps(data).encode()
        self._socket.sendto(encoded_data, (address.exploded, self._port))

    def _handle_join_network(self, address: IPv4Address, request: Json) -> None:
        logging.debug(f"Handling join network request from {address}")
        self._cache[address] = request["dht_node_id"]

    def _handle_get_random_nodes(self, address: IPv4Address, request: Json) -> None:
        blocklist = request["blocklist"]
        blocklist.append(self._dht_server.node.long_id)
        filtered_cache = {k: v for k, v in self._cache.items() if v not in blocklist}

        random_nodes = random.sample(list(filtered_cache.keys()), k=4)
        response = {
            "command": 7,
            "nodes": random_nodes
        }
        self._send(address, response)

    @property
    def _port(self) -> Int:
        return LEVEL_D_PORT

    def _host_dht(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._loop.set_debug(True)
        self._dht_server = Server()
        self._loop.run_until_complete(self._dht_server.listen(LEVEL_0_PORT))

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
