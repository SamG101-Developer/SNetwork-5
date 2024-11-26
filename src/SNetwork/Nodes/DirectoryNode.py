import json

from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
from SNetwork.CommunicationStack.Layers_1stParty.LayerD import LayerD
from SNetwork.Config import DIRECTORY_SERVICE_PRIVATE_FILE
from SNetwork.Managers.KeyManager import KeyManager
from SNetwork.Nodes.Node import Node
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Bytes, Int


class DirectoryNode(Node):
    _name: str

    def __init__(self, name, hashed_username: Bytes, hashed_password: Bytes, port: Int, identifier: Bytes, static_key_pair: AsymmetricKeyPair) -> None:
        self._name = name

        # Create the communication stack, and the bootstrapper layer.
        self._communication_stack = CommunicationStack(hashed_username, port)
        self._bootstrapper = LayerD(self._communication_stack, self._communication_stack._socket_ln, True, identifier, static_key_pair)

        # Check if the node has been registered before.
        has_info = KeyManager.has_info(hashed_username)
        if not has_info:
            self._boot_sequence(hashed_username, hashed_password)

        # Save the information of the node and start the communication stack.
        self._info = KeyManager.get_info(hashed_username)
        self._communication_stack.start(self._info, self._bootstrapper)

    def _boot_sequence(self, hashed_username: Bytes, hashed_password: Bytes) -> None:
        # Set the keys.
        with open(DIRECTORY_SERVICE_PRIVATE_FILE % self._name, "rb") as file:
            private_directory_service_entry = json.load(file)
            logger = isolated_logger(LoggerHandlers.SYSTEM)

        # Store the certificate and other information in the key store.
        KeyManager.set_info(
            identifier=bytes.fromhex(private_directory_service_entry["identifier"]),
            secret_key=bytes.fromhex(private_directory_service_entry["secret_key"]),
            public_key=bytes.fromhex(private_directory_service_entry["public_key"]),
            certificate=None,
            hashed_profile_username=hashed_username,
            hashed_profile_password=hashed_password)
