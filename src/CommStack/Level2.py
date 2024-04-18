"""
The Node class sends commands to other nodes, over an encrypted connection. The connection is setup by the SecureSocket
class, isolating the layers of the communication stack. The Node class is responsible for sending and receiving messages
from other nodes, and is the primary interface for the application to communicate with other nodes.
"""

from enum import Enum
from ipaddress import IPv6Address
from threading import Thread
import json

from Utils.Types import Json
from src.CommStack.Level1 import Level1, Level1Protocol
from src.CommStack.LevelN import LevelN, LevelNProtocol, Connection
from src.Crypt.Symmetric import SymmetricEncryption
from src.Utils.Types import Int


class Level2Protocol(Enum, LevelNProtocol):
    ...


class Level2(LevelN):
    _level1: Level1

    def __init__(self):
        self._level1 = Level1()

    def _listen(self) -> None:
        # Bind the secure socket to port 40001.
        self._socket.bind(("::", self.port))

        # Listen for incoming encrypted requests, and handle them in a new thread.
        while True:
            data, address = self._socket.recvfrom(4096)

            # Split the connection token from the ciphertext, and ensure a connection with this token exists.
            token, encrypted_data = data[:32], data[32:]
            connection = self._level1._conversations.get(token)
            if not connection or not connection.e2e_master_key:
                continue

            # Decrypt the ciphertext with the key corresponding to the connection token.
            decrypted_data = SymmetricEncryption.decrypt(connection.e2e_master_key, encrypted_data)
            request = json.loads(decrypted_data)

            # Ensure that the connection token received matches the connection token embedded in the request.
            assert request["token"] == token.hex(), "Token mismatch."

            # Handle the command in a new thread.
            Thread(target=self._handle_command, args=(IPv6Address(address[0]), request)).start()

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        ...

    def _send(self, connection: Connection, data: Json) -> None:
        # Check the connection is valid.
        if connection.state != Level1Protocol.AcceptConnection or not connection.e2e_master_key:
            return

        # Encrypt and send the request.
        raw_data = json.dumps(data).encode()
        encrypted_data = connection.token + SymmetricEncryption.encrypt(connection.e2e_master_key, raw_data)
        self._socket.sendto(encrypted_data, (connection.address.exploded, self.port))

    @property
    def port(self) -> Int:
        return 40002
