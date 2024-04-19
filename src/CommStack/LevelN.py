from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from ipaddress import IPv4Address
from socket import socket as Socket, AF_INET, SOCK_DGRAM

from PyQt6.QtCore import QObject, pyqtSignal

from src.Utils.Types import Bytes, Json, Int, Optional
from src.Crypt.AsymmetricKeys import SecKey


@dataclass
class Connection:
    address: IPv4Address
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

    def __init__(self):
        self._socket = Socket(AF_INET, SOCK_DGRAM)

    @abstractmethod
    def _listen(self) -> None:
        ...

    @abstractmethod
    def _handle_command(self, address: IPv4Address, request: Json) -> None:
        ...

    @abstractmethod
    def _send(self, connection: Connection, data: Json) -> None:
        ...

    @property
    @abstractmethod
    def _port(self) -> Int:
        ...

    def __del__(self):
        self._socket.close()
