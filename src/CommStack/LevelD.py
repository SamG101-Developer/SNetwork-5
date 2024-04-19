from enum import Enum
from ipaddress import IPv6Address
from threading import Thread
import json, os

from PyQt6.QtWidgets import QErrorMessage

from src.CommStack.Level0 import Level0
from src.CommStack.LevelN import LevelN, LevelNProtocol
from src.Crypt.Hash import Hasher, SHA3_256
from src.Crypt.Sign import Signer
from src.Utils.Types import Json, Int
from src.CONFIG import LEVEL_D_PORT, DIRECTORY_IP


class LevelDProtocol(LevelNProtocol, Enum):
    JoinNetwork = 0
    Bootstrap = 1


class LevelD(LevelN):
    _level0: Level0

    def __init__(self, level0: Level0):
        self._level0 = level0

        # Start listening for incoming connections and bootstrap the network.
        Thread(target=self._listen).start()
        Thread(target=self._bootstrap).start()

    def _bootstrap(self) -> None:
        # Make sure keys exist.
        if not os.path.exists("_crypt"):
            os.mkdir("_crypt")
            this_static_key_pair = Signer.generate_key_pair()
            open("_crypt/public_key.pem", "w").write(this_static_key_pair.public_key.str)
            open("_crypt/secret_key.pem", "w").write(this_static_key_pair.secret_key.str)

        # Join the network by sending a request to the directory node.
        this_static_public_key = open("_crypt/public_key.pem").read()
        this_identifier = Hasher.hash(this_static_public_key.encode(), SHA3_256())
        request = {
            "command": LevelDProtocol.JoinNetwork.value}

        # Send the request to the directory node.
        self._send(DIRECTORY_IP, request)

    def _listen(self) -> None:
        self._socket.bind(("::", self._port))
        while True:
            data, address = self._socket.recvfrom(1024)
            request = json.loads(data)
            Thread(target=self._handle_command, args=(IPv6Address(address[0]), request)).start()

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        if "command" not in request:
            return

        command = request["command"]
        match command:
            case LevelDProtocol.Bootstrap.value:
                self._handle_bootstrap(request)

    def _send(self, address: IPv6Address, data: Json) -> None:
        encoded_data = json.dumps(data).encode()
        self._socket.sendto(encoded_data, (address.exploded, self._port))

    @property
    def _port(self) -> Int:
        return LEVEL_D_PORT

    def _handle_bootstrap(self, request: Json) -> None:
        # Ge this node's identifier.
        this_identifier = Hasher.hash(open("_crypt/public_key.pem").read().encode(), SHA3_256())

        # Popup message if there are currently no nodes in the network.
        node_ip_addresses = request["ips"]
        if not node_ip_addresses:
            error_message = QErrorMessage()
            error_message.showMessage("No nodes in the network.")
            error_message.exec()
            return

        # Add the node to the DHT.
        for ip in node_ip_addresses:
            ip = IPv6Address(bytes.fromhex(ip))
            if self._level0.join(ip): break

        # Place node info on the DHT.
        key_file = f"_crypt/{this_identifier.hex()}.pem"
        open(key_file, "w").write(open("_crypt/public_key.pem").read())
        self._level0.put(key_file)
