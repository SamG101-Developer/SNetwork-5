from __future__ import annotations
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, Connection, LayerNProtocol, RawRequest
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Json, Int

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.Managers.KeyManager import KeyStoreData


class Layer1Protocol(LayerNProtocol, Enum):
    pass


class Layer1(LayerN):
    _layer_application: LayerN

    def __init__(self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket, application: LayerN) -> None:
        super().__init__(stack, node_info, Layer1Protocol, socket, isolated_logger(LoggerHandlers.LAYER_1))
        self._layer_application = application
        self._logger.info("Layer 1 Ready")

    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: Json) -> None:
        ...

    def _send(self, conn: Connection, req: RawRequest) -> None:
        ...
