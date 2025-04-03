from __future__ import annotations

from abc import abstractmethod, ABC
from ipaddress import IPv6Address
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.CommunicationStack.Layers_1stParty.LayerN import RawRequest
    from SNetwork.Utils.Types import Int


class Layer1_Abstract(ABC):
    """
    Layer1_Abstract is an abstract class, which defines the interface for the application layers that are wrapped into
    Layer 1. It is responsible for sending and receiving data from the application into the communication stack.
    """

    _stack: CommunicationStack

    def __init__(self, stack: CommunicationStack) -> None:
        self._stack = stack

    @abstractmethod
    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: RawRequest) -> None:
        ...
