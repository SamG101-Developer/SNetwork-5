import logging
import pickle
import time
from threading import Thread
from typing import Optional

import caseconverter

from SNetwork.CommunicationStack.Layers_1stParty.Layer1 import Layer1
from SNetwork.CommunicationStack.Layers_1stParty.Layer2 import Layer2
from SNetwork.CommunicationStack.Layers_1stParty.Layer3 import Layer3
from SNetwork.CommunicationStack.Layers_1stParty.Layer4 import Layer4
from SNetwork.CommunicationStack.Layers_1stParty.LayerD import LayerD
from SNetwork.CommunicationStack.Layers_1stParty.LayerN import AbstractRequest, EncryptedRequest
from SNetwork.CommunicationStack.Layers_2ndParty.HTTP.Layer1_Http import Layer1_Http
from SNetwork.Managers.KeyManager import KeyStoreData
from SNetwork.QuantumCrypto.Symmetric import SymmetricEncryption
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Socket import Socket
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
    _listen_thread: Thread
    _socket: Socket

    def __init__(self, hashed_username: Bytes, port: Int):
        # Set the layers to None, as they are created in the start method.
        self._layer1 = None
        self._layer2 = None
        self._layer3 = None
        self._layer4 = None
        self._layerD = None

        # Create the sockets for the stack.
        self._port = port
        self._socket = Socket()
        self._logger = isolated_logger(LoggerHandlers.SYSTEM)

        # Bind the sockets to the default IPv6 address and the specified port.
        self._socket.bind(self._port)
        self._logger.info(f"Bound to port {self._port}.")
        self._listen_thread = Thread(target=self._listen, daemon=True)
        self._listen_thread.start()

    def __del__(self) -> None:
        self._socket and self._socket.close()

    def start(self, info: KeyStoreData) -> None:
        self._logger.info(f"Communication stack started @{info.identifier.hex()}.")

        # Create the layers of the stack.
        self._layer4 = Layer4(self, info, self._socket)
        self._layer3 = Layer3(self, info, self._socket)
        self._layer2 = Layer2(self, info, self._socket)
        self._layer1 = Layer1(self, info, self._socket)

        # Register known application layers.
        pass

    @property
    def _layers(self):
        return [self._layer1, self._layer2, self._layer3, self._layer4, self._layerD]

    def _listen(self) -> None:
        # Listen for incoming raw requests, and handle them in a new thread.
        while True:
            data, ip, port = self._socket.recvfrom(24_000)

            try:
                response = AbstractRequest.deserialize(data)
                if not response: continue
            except pickle.UnpicklingError:
                self._logger.warning(f"Received invalid-formatted data from {ip}:{port}.")
                continue

            tunnelled_response = None

            # Handle secure p2p requests.
            if response.secure:
                token, encrypted_data = response.conn_tok, response.ciphertext

                # Ensure the token represents a connection that both exists, and is in the accepted state.
                if token in self._layer4._conversations.keys():
                    e2e_key = self._layer4._conversations[token].e2e_key
                    decrypted_data = SymmetricEncryption.decrypt(data=encrypted_data, key=e2e_key)
                    response = pickle.loads(decrypted_data)

                    # If the response is still encrypted, it is a tunnel request.
                    if isinstance(response, EncryptedRequest):
                        self._logger.debug(f"Received tunnelled encrypted data from {ip}:{port}.")
                        tunnelled_response = response
                        e2e_key = self._layer2._participating_route_keys[response.conn_tok]
                        decrypted_data = SymmetricEncryption.decrypt(data=response.ciphertext, key=e2e_key)
                        response = pickle.loads(decrypted_data)

                # Otherwise, the connection is unknown, and the response is ignored.
                else:
                    logging.warning(f"Received data from unknown token {token}.")
                    continue

            self._logger.debug(f"<- Received '{response}' from {ip}:{port}.")

            # Handle non-secure requests
            while not all(self._layers):
                self._logger.debug("Waiting for layers to be created...")
                time.sleep(1)
                continue

            layer = [x for x in self._layers if hasattr(x, f"_handle_{caseconverter.snakecase(str(response))}")][0]
            if tunnelled_response is None:
                Thread(target=layer._handle_command, args=(ip, port, response)).start()
            else:
                Thread(target=layer._handle_command, args=(ip, port, response, tunnelled_response)).start()


__all__ = ["CommunicationStack"]
