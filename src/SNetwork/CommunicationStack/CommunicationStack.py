import logging
from ipaddress import IPv6Address
from socket import socket as Socket, SOCK_DGRAM, AF_INET6
from threading import Thread

from SNetwork.CommunicationStack.Layers_1stParty.Layer1 import Layer1
from SNetwork.CommunicationStack.Layers_1stParty.Layer2_old import Layer2
from SNetwork.CommunicationStack.Layers_1stParty.Layer3 import Layer3
from SNetwork.CommunicationStack.Layers_1stParty.Layer4 import Layer4
from SNetwork.CommunicationStack.Layers_2ndParty.LayerHTTP.LayerHttp import LayerHTTP
from SNetwork.Config import DEFAULT_IPV6
from SNetwork.QuantumCrypto.Symmetric import SymmetricEncryption
from SNetwork.Managers.KeyManager import KeyStoreData
from SNetwork.Utils.Json import SafeJson
from SNetwork.Utils.Types import Bytes, Int


class CommunicationStack:
    """
    The Communication Stack class is used to create the layers of the communication stack. The stack is accessible to
    each layer of the stack, as some-cross layer communication is required.
    """

    _layer1: Layer1
    _layer2: Layer2
    _layer3: Layer3
    _layer4: Layer4

    _port: Int
    _socket_ln: Socket

    def __init__(self, hashed_username: Bytes, port: Int):
        # Create the sockets for the stack.
        self._port = port
        self._socket_ln = Socket(family=SOCK_DGRAM, type=AF_INET6)

        # Bind the sockets to the default IPv6 address and the specified port.
        self._socket_ln.bind((DEFAULT_IPV6, self._port))

    def __del__(self) -> None:
        self._socket_ln and self._socket_ln.close()

    def start(self, info: KeyStoreData) -> None:
        # Create the layers of the stack.
        self._layer4 = Layer4(self, info, self._socket_ln)
        self._layer3 = Layer3(self, info, self._socket_ln)
        self._layer2 = Layer2(self, info, self._socket_ln)
        self._layer1 = Layer1(self, info, self._socket_ln, LayerHTTP(self, self._port))

    def _listen(self) -> None:
        # Listen for incoming raw requests, and handle them in a new thread.
        while True:
            data, address = self._socket_ln.recvfrom(4096)
            request = SafeJson.loads(data)  # error handler -> json error back to sender
            if not request: continue

            # Handle secure requests
            if request["secure"]:
                token, encrypted_data = request["token"], request["data"]

                # Ensure the token represents a connection that both exists, and is in the accepted state.
                if token in self._layer4._conversations.keys() and self._layer4._conversations[token].is_accepted():
                    e2e_key = self._layer4._conversations[token].e2e_primary_keys[int(request["message_number"]) // 100]
                    decrypted_data = SymmetricEncryption.decrypt(data=encrypted_data, key=e2e_key)
                    decrypted_json = SafeJson.loads(decrypted_data)
                    request = decrypted_json

                # Otherwise, the connection is unknown, and the request is ignored.
                else:
                    logging.warning(f"Received request from unknown token {token}.")
                    continue

            # Handle non-secure requests
            Thread(target=globals()[f"Layer{request["layer"]}"]._handle_command, args=(IPv6Address(address[0]), address[1], request)).start()


__all__ = ["CommunicationStack"]
