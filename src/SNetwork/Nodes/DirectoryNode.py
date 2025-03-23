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
        self._name = name

        # Create the communication stack, and the bootstrapper layer.
        self._stack = CommunicationStack(hashed_username, port)

        # Check if the node has been registered before.
        has_info = KeyManager.has_info(hashed_username)
        if not has_info:
            self._boot_sequence(hashed_username, hashed_password, identifier, static_key_pair)

        # Save the information of the node.
        self._info = KeyManager.get_info(hashed_username)

        # Start the special directory layer communications and start the communication stack.
        self._stack.start(self._info)
        self._boot = LayerD(self._stack, self._stack._socket_ln, True, self._info.identifier, self._info.certificate, static_key_pair)
        self._stack._logger.info(f"Directory Node started.")

    def _boot_sequence(
            self, hashed_username: Bytes, hashed_password: Bytes, identifier: Bytes = None,
            static_key_pair: AsymmetricKeyPair = None) -> None:
        self._stack._logger.info(f"Registering directory node {identifier.hex()}.")
        self._generate_certificate(hashed_username, hashed_password, identifier, static_key_pair)
