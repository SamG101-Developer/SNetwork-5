import time
from ipaddress import IPv6Address

from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
from SNetwork.CommunicationStack.Layers_1stParty.LayerD import LayerD
from SNetwork.CommunicationStack.Layers_2ndParty.HTTP.Layer1_Http import Layer1_Http
from SNetwork.Managers.KeyManager import KeyManager
from SNetwork.Nodes.AbstractNode import AbstractNode
from SNetwork.Utils.Types import Bytes, Int, Tuple, Dict


class NodeCache:
    """
    A cache containing other nodes to try to connect to. The cache is maintained in a file, and is used to keep track of
    other nodes that have been connected to in the past. Old nodes are removed from the cache, and new nodes are added
    to the cache by asking the directory service, or a node, for a list of known nodes.
    """

    _nodes: Dict[Bytes, Tuple[Bytes, IPv6Address, Int]]

    def __init__(self) -> None:
        self._nodes = {}

    def _load_local_cache(self, identifier: Bytes) -> None:
        pass


class Node(AbstractNode):
    _cache: NodeCache

    def __init__(self, hashed_username: Bytes, hashed_password: Bytes, port: Int) -> None:
        # Create the communication stack, and the bootstrapper layer.
        self._info = KeyManager.get_info(hashed_username)
        self._stack = CommunicationStack(hashed_username, port)
        self._stack._layerD = LayerD(
            self._stack, self._info, self._stack._socket, False, self._info.identifier, self._info.certificate)

        # Save the information of the node and start the communication stack.
        time.sleep(2)
        self._stack.start(self._info)
        self._stack._layerD.request_bootstrap()
        self._stack._logger.info(f"Node started.")

        # Join the routing network.
        tester = self._info.hashed_username.hex() == "e2fee945baae91d9f81c5d4c218f62f2d865ab650a5c8aaae721c537a469981e"
        self._stack._layer1.register_application(Layer1_Http(self._stack, enable_proxy=tester))
        if tester:
            time.sleep(2)
            self._stack._layer2.create_route()
