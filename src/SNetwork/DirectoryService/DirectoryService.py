from ipaddress import IPv6Address
import asyncio, logging

from SNetwork.Utils.Types import Json, Int, Dict


class DirectoryService:
    _cache: Dict[IPv6Address, Int]
    _log: logging.Logger
    _loop: asyncio.AbstractEventLoop

    # TODO


__all__ = ["DirectoryService"]
