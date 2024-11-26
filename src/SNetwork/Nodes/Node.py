from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
from SNetwork.CommunicationStack.Layers_1stParty.LayerD import LayerD
from SNetwork.Managers.KeyManager import KeyManager, KeyStoreData
from SNetwork.Utils.Types import Bytes, Int


class Node:
    _communication_stack: CommunicationStack
    _bootstrapper: LayerD
    _info: KeyStoreData

    def __init__(self, hashed_username: Bytes, hashed_password: Bytes, port: Int) -> None:
        # Create the communication stack, and the bootstrapper layer.
        self._communication_stack = CommunicationStack(hashed_username, port)
        self._bootstrapper = LayerD(self._communication_stack, self._communication_stack._socket_ln, False)

        # Check if the node has been registered before.
        has_info = KeyManager.has_info(hashed_username)
        if not has_info:
            self._boot_sequence(hashed_username, hashed_password)

        # Save the information of the node and start the communication stack.
        self._info = KeyManager.get_info(hashed_username)
        self._communication_stack.start(self._info, self._bootstrapper)

    def _boot_sequence(self, hashed_username: Bytes, hashed_password: Bytes) -> None:
        # Register the node against the network.
        self._bootstrapper.join_network()
        while not self._bootstrapper._certificate: continue

        # Store the certificate and other information in the key store.
        KeyManager.set_info(
            identifier=self._bootstrapper._this_identifier,
            secret_key=self._bootstrapper._this_static_key_pair.secret_key,
            public_key=self._bootstrapper._this_static_key_pair.public_key,
            certificate=self._bootstrapper._certificate,
            hashed_profile_username=hashed_username,
            hashed_profile_password=hashed_password)
