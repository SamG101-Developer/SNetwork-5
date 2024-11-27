import pickle

from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
from SNetwork.CommunicationStack.Layers_1stParty.LayerD import LayerD
from SNetwork.Config import PROFILE_CACHE
from SNetwork.Managers.KeyManager import KeyManager, KeyStoreData
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Types import Bytes, Int


class Node:
    _stack: CommunicationStack
    _boot: LayerD
    _info: KeyStoreData

    def __init__(self, hashed_username: Bytes, hashed_password: Bytes, port: Int) -> None:
        # Create the communication stack, and the bootstrapper layer.
        self._stack = CommunicationStack(hashed_username, port)
        self._boot = LayerD(self._stack, self._stack._socket_ln, False)

        # Check if the node has been registered before.
        if not KeyManager.has_info(hashed_username):
            self._boot_sequence(hashed_username, hashed_password)
        else:
            self._stack._logger.info(f"Node already registered.")

        # Save the information of the node and start the communication stack.
        self._info = KeyManager.get_info(hashed_username)
        self._stack.start(self._info)
        self._stack._logger.info(f"Node started.")

        # Wait for the node cache to be populated.
        while not self._boot._node_cache: continue

        # Open the node cache and load the node information.
        with SafeFileOpen(PROFILE_CACHE % hashed_username.hex(), "rb") as file:
            node_info = pickle.load(file)

        # Try to connect to a node in the distributed hash table network.
        for node in node_info:
            connection = self._stack._layer4.connect(*node[:3])
            if connection: self._stack._layer3.join_distributed_hash_table_network(connection)

    def _boot_sequence(self, hashed_username: Bytes, hashed_password: Bytes) -> None:
        # Register the node against the network.
        self._boot.join_network()
        while not self._boot._certificate: continue

        # Store the certificate and other information in the key store.
        KeyManager.set_info(KeyStoreData(
            identifier=self._boot._this_identifier,
            secret_key=self._boot._this_static_key_pair.secret_key,
            public_key=self._boot._this_static_key_pair.public_key,
            certificate=self._boot._certificate,
            hashed_username=hashed_username,
            hashed_password=hashed_password))
