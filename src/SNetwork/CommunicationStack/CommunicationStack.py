import logging
import pickle
import time
from ipaddress import IPv6Address
from socket import socket as Socket, SOCK_DGRAM, AF_INET6
from threading import Thread
from typing import Optional

from SNetwork.CommunicationStack.Layers_1stParty.Layer1 import Layer1
from SNetwork.CommunicationStack.Layers_1stParty.Layer2 import Layer2
from SNetwork.CommunicationStack.Layers_1stParty.Layer3 import Layer3
from SNetwork.CommunicationStack.Layers_1stParty.Layer4 import Layer4
from SNetwork.CommunicationStack.Layers_1stParty.LayerD import LayerD
from SNetwork.CommunicationStack.Layers_1stParty.LayerN import AbstractRequest
from SNetwork.CommunicationStack.Layers_2ndParty.LayerHTTP.LayerHttp import LayerHTTP
from SNetwork.Config import DEFAULT_IPV6
from SNetwork.QuantumCrypto.Symmetric import SymmetricEncryption
from SNetwork.Managers.KeyManager import KeyStoreData
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Bytes, Int


class CommunicationStack:
    """
    The Communication Stack class is used to create the layers of the communication stack. The stack is accessible to
    each layer of the stack, as some-cross layer communication is required.
    """

    _layer1: Optional[Layer1]
    _layer2: Optional[Layer2]
    _layer3: Optional[Layer3]
    _layer4: Optional[Layer4]
    _layerD: Optional[LayerD]

    _port: Int
    _socket_ln: Socket

    def __init__(self, hashed_username: Bytes, port: Int):
        # Set the layers to None, as they are created in the start method.
        self._layer1 = None
        self._layer2 = None
        self._layer3 = None
        self._layer4 = None
        self._layerD = None

        # Create the sockets for the stack.
        self._port = port
        self._socket_ln = Socket(family=AF_INET6, type=SOCK_DGRAM)
        self._logger = isolated_logger(LoggerHandlers.SYSTEM)

        # Bind the sockets to the default IPv6 address and the specified port.
        self._socket_ln.bind((DEFAULT_IPV6, self._port))
        self._logger.info(f"Bound to port {self._port}.")
        Thread(target=self._listen).start()

    def __del__(self) -> None:
        self._socket_ln and self._socket_ln.close()

    def start(self, info: KeyStoreData) -> None:
        # Create the layers of the stack.
        self._layer4 = Layer4(self, info, self._socket_ln)
        self._layer3 = Layer3(self, info, self._socket_ln)
        self._layer2 = Layer2(self, info, self._socket_ln)
        self._layer1 = Layer1(self, info, self._socket_ln, LayerHTTP(self))

    def _listen(self) -> None:
        # Listen for incoming raw requests, and handle them in a new thread.
        while True:
            data, address = self._socket_ln.recvfrom(20_000)
            request = AbstractRequest.deserialize(data)
            if not request: continue

            self._logger.debug(f"<- Received request from {address}.")

            # Handle secure requests
            if request.secure:
                token, encrypted_data = request.token, request.data

                # Ensure the token represents a connection that both exists, and is in the accepted state.
                if token in self._layer4._conversations.keys() and self._layer4._conversations[token].is_accepted():
                    e2e_key = self._layer4._conversations[token].e2e_primary_keys[int(request.request_metadata.message_number) // 100]
                    decrypted_data = SymmetricEncryption.decrypt(data=encrypted_data, key=e2e_key)
                    decrypted_json = pickle.loads(decrypted_data)
                    request = decrypted_json

                # Otherwise, the connection is unknown, and the request is ignored.
                else:
                    logging.warning(f"Received request from unknown token {token}.")
                    continue

            # Handle non-secure requests
            layer = getattr(self, f"_layer{request.request_metadata.stack_layer}")
            while not layer:
                self._logger.debug(f"Waiting for layer {request.request_metadata.stack_layer}...")
                time.sleep(1)
                continue
            Thread(target=layer._handle_command, args=(IPv6Address(address[0]), address[1], request)).start()


__all__ = ["CommunicationStack"]
