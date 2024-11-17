from ipaddress import IPv6Address

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, Connection, LayerNProtocol, AbstractRequest
from SNetwork.Utils.Types import Json


class Layer1(LayerN):
    _layer_application: LayerN

    def __init__(self, stack, socket, application: LayerN) -> None:
        super().__init__(stack, socket)
        self._layer_application = application

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        self._layer_application._handle_command(address, request)

    def _send(self, connection: Connection, protocol: LayerNProtocol, request: AbstractRequest) -> None:
        self._layer_application._send(connection, protocol, request)
