from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from ipaddress import IPv6Address
from socket import socket as Socket

from src.Utils.Types import Bool, Bytes, Json, Int, Optional
from src.Crypt.AsymmetricKeys import SecKey


@dataclass
class Connection:
    address: IPv6Address
    identifier: Bytes
    token: Bytes
    state: LevelNProtocol
    challenge: Optional[Bytes]
    ephemeral_public_key: Optional[Bytes]
    ephemeral_secret_key: Optional[SecKey]
    e2e_master_key: Optional[Bytes]


class LevelNProtocol:
    ...


class LevelN(ABC):
    _socket: Socket

    @abstractmethod
    def _listen(self) -> None:
        ...

    @abstractmethod
    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        ...

    @abstractmethod
    def _send(self, connection: Connection, data: Json) -> None:
        ...

    @property
    @abstractmethod
    def _port(self) -> Int:
        ...
