import logging
from ipaddress import IPv6Address
from socket import socket as Socket, SOCK_DGRAM, AF_INET6, SOCK_STREAM
from threading import Thread

from SNetwork.CommunicationStack.Layer1 import Layer1
from SNetwork.CommunicationStack.Layer2 import Layer2
from SNetwork.CommunicationStack.Layer3 import Layer3
from SNetwork.CommunicationStack.Layer4 import Layer4
from SNetwork.CommunicationStack.LayerD import LayerD
from SNetwork.Crypt.AsymmetricKeys import KeyPair
from SNetwork.Crypt.Symmetric import SymmetricEncryption
from SNetwork.Managers.KeyManager import KeyManager
from SNetwork.Managers.ProfileManager import ProfileManager
from SNetwork.Utils.Json import SafeJson
from SNetwork.Config import DEFAULT_IPV6, PORT


class CommunicationStack:
    """
    The Communication Stack class is used to create the layers of the communication stack. The stack is accessible to
    each layer of the stack, as some-cross layer communication is required.
    """

    _layer1: Layer1
    _layer2: Layer2
    _layer3: Layer3
    _layer4: Layer4
    _layerD: LayerD

    _socket: Socket
    _socket_l1: Socket

    def __init__(self, is_directory_node: bool):
        self._socket = Socket(family=SOCK_DGRAM, type=AF_INET6)
        info = KeyManager.get_info(ProfileManager.CURRENT_HASHED_USERNAME)

        if not is_directory_node:
            self._socket_l1 = Socket(family=SOCK_STREAM, type=AF_INET6)

            # Create the layers of the stack.
            self._layer4 = Layer4(self, self._socket)
            self._layer3 = Layer3(self, self._socket)
            self._layer2 = Layer2(self, self._socket)
            self._layer1 = Layer1(self, self._socket_l1)
            self._layerD = LayerD(self, self._socket, False, info["identifier"], KeyPair(info["secret_key"], info["public_key"]))

        else:
            self._layerD = LayerD(self, self._socket, False, info["identifier"], KeyPair(info["secret_key"], info["public_key"]))

    def _listen(self) -> None:
        # Bind the insecure socket to port 40,000.
        self._socket.bind((DEFAULT_IPV6, PORT))

        # Listen for incoming raw requests, and handle them in a new thread.
        while True:
            data, address = self._socket.recvfrom(4096)
            request = SafeJson.loads(data)  # error handler -> json error back to sender
            if not request: continue

            # Handle secure requests
            if request["secure"]:
                token, encrypted_data = request["token"], request["data"]

                # Ensure the token represents a connection that both exists, and is in the accepted state.
                if token in self._layer4._conversations.keys() and self._layer4._conversations[token].is_accepted():
                    e2e_key = self._layer4._conversations[token].e2e_primary_key
                    decrypted_data = SymmetricEncryption.decrypt(data=encrypted_data, key=e2e_key)
                    decrypted_json = SafeJson.loads(decrypted_data)
                    request = decrypted_json

                # Otherwise, the connection is unknown, and the request is ignored.
                else:
                    logging.warning(f"Received request from unknown token {token}.")
                    continue

            # Handle non-secure requests
            Thread(target=globals()[f"Layer{request["layer"]}"]._handle_command, args=(IPv6Address(address[0]), request)).start()


__all__ = ["CommunicationStack"]
