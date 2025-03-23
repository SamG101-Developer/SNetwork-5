from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
from SNetwork.CommunicationStack.Layers_1stParty.LayerD import LayerD
from SNetwork.Managers.KeyManager import KeyManager
from SNetwork.Nodes.Node import Node
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.Utils.Types import Bytes, Int, Str


class DirectoryNode(Node):
    _name: Str

    def __init__(
            self, name, hashed_username: Bytes, hashed_password: Bytes, port: Int, identifier: Bytes,
            static_key_pair: AsymmetricKeyPair) -> None:
        # Create the communication stack, and the bootstrapper layer.
        self._name = name
        self._stack = CommunicationStack(hashed_username, port)
        self._info = KeyManager.get_info(hashed_username)

        # Start the special directory layer communications and start the communication stack.
        self._stack.start(self._info)
        self._boot = LayerD(
            self._stack, self._info, self._stack._socket_ln, True, self._info.identifier, self._info.certificate,
            static_key_pair)
        self._stack._logger.info(f"Directory Node started.")
