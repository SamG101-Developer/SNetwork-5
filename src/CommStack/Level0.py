import asyncio, logging
import random

from src.kademlia.network import Server
from src.CONFIG import LEVEL_D_PORT, DIRECTORY_IP, LEVEL_0_PORT


class Level0:
    _log: logging.Logger
    _server: Server

    def __init__(self):
        self._log = logging.getLogger("kademlia")
        self._log.setLevel(logging.DEBUG)
        self.join()

    def join(self) -> None:
        asyncio.run(self._run())

    async def _run(self) -> None:
        self._server = Server()
        await self._server.listen(40_000)
        await self._server.bootstrap([(DIRECTORY_IP.exploded, LEVEL_0_PORT)])

    def __del__(self):
        try: self._server.stop()
        except RuntimeError: pass

    def put(self, file_name: str, file_contents: bytes) -> None:
        self._server.set(file_name, file_contents)

    async def get(self, file_name: str) -> bytes:
        return await self._server.get(file_name)

    def leave(self) -> None:
        self._server.stop()

    def get_random_node(self):
        nodes = self._server.protocol.router.buckets.flat()
        random_node = random.choice(nodes)
        print(f"{random_node}")
        return random_node

    @property
    def node_key(self):
        return self._server.node.long_id
