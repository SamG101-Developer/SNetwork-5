import asyncio, logging
import json
import random

from src.Utils.Types import List, Bytes
from src.kademlia.network import Server
from src.CONFIG import LEVEL_D_PORT, DIRECTORY_IP, LEVEL_0_PORT


class Level0:
    _log: logging.Logger
    _server: Server
    _loop: asyncio.AbstractEventLoop

    def __init__(self):
        self._log = logging.getLogger("kademlia")
        self._log.setLevel(logging.DEBUG)
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        self.join()

    def join(self) -> None:
        self._loop.run_until_complete(self._run())

    async def _run(self) -> None:
        self._server = Server()
        await self._server.listen(40_000)
        await self._server.bootstrap([(DIRECTORY_IP.exploded, LEVEL_0_PORT)])

    def put(self, file_name: str, file_contents: bytes) -> None:
        task = self._server.set(file_name, file_contents)
        self._loop.run_until_complete(task)

    def get(self, file_name: str) -> bytes:
        task = self._server.get(file_name)
        contents = self._loop.run_until_complete(task)
        open(f"_store/{file_name}", "wb").write(contents)
        return contents

    def leave(self) -> None:
        try: self._server.stop()
        except RuntimeError: pass

    def get_random_node(self, exclude_list: List[Bytes]):
        nodes = self._server.protocol.router.buckets.flat()
        random_node = random.choice(nodes)
        while bytes.fromhex(json.loads(random_node)["id"]) in exclude_list:
            random_node = random.choice(nodes)
        print(f"{random_node}")
        return random_node

    @property
    def node_key(self):
        return self._server.node.long_id

    def __del__(self):
        try: self._server.stop()
        except RuntimeError: pass
