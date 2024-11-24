import json

from SNetwork.Config import DIRECTORY_SERVICE_PRIVATE_FILE
from SNetwork.Managers.KeyManager import KeyManager
from SNetwork.Nodes.Node import Node
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Bytes, Int


class DirectoryNode(Node):
    _name: str

    def __init__(self, name, hashed_username: Bytes, hashed_password: Bytes, port: Int) -> None:
        self._name = name
        super().__init__(hashed_username, hashed_password, port)

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
