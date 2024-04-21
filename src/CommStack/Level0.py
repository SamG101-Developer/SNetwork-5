from kademlia.network import Server
import asyncio, logging

from src.CONFIG import LEVEL_D_PORT, DIRECTORY_IP


class Level0:
    _log: logging.Logger
    _server: Server

    def __init__(self):
        self._log = logging.getLogger("kademlia")
        self._log.setLevel(logging.DEBUG)
        asyncio.run(self._run())

    async def _run(self) -> None:
        self._server = Server()
        await self._server.listen(40_000)
        await self._server.bootstrap([(DIRECTORY_IP, LEVEL_D_PORT)])

    def __del__(self):
        self._server.stop()

    def put(self, file_name: str, file_contents: bytes) -> None:
        self._server.set(file_name, file_contents)

    async def get(self, file_name: str) -> bytes:
        return await self._server.get(file_name)
