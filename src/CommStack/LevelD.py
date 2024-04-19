from enum import Enum
from ipaddress import IPv4Address
from threading import Thread
import logging, json, os

from PyQt6.QtWidgets import QErrorMessage
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from src.Crypt.AsymmetricKeys import PubKey
from src.CommStack.Level0 import Level0
from src.CommStack.LevelN import LevelN, LevelNProtocol
from src.Crypt.Hash import Hasher, SHA3_256
from src.Crypt.Sign import Signer
from src.Utils.Address import my_address
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
        logging.debug("Layer D Ready")

    def _bootstrap(self) -> None:
        logging.debug("Bootstrapping network.")

        # Make sure keys exist.
        if not os.path.exists("_crypt/secret_key.pem"):
            logging.debug("Generating keys.")
            os.mkdir("_crypt")
            this_static_key_pair = Signer.generate_key_pair()
            identifier = Hasher.hash(this_static_key_pair.public_key.bytes, SHA3_256())
            open("_crypt/public_key.pem", "w").write(this_static_key_pair.public_key.str)
            open("_crypt/secret_key.pem", "w").write(this_static_key_pair.secret_key.str)
            open("_crypt/identifier.txt", "w").write(identifier.hex())
        logging.debug("Created keys, joining network.")

        # Join the network by sending a request to the directory node.
        request = {
            "command": LevelDProtocol.JoinNetwork.value}

        # Send the request to the directory node.
        self._send(DIRECTORY_IP, request)

    def _listen(self) -> None:
        self._socket.bind(("", self._port))
        while True:
            data, address = self._socket.recvfrom(1024)
            request = json.loads(data)
            Thread(target=self._handle_command, args=(IPv4Address(address[0]), request)).start()

    def _handle_command(self, address: IPv4Address, request: Json) -> None:
        if "command" not in request:
            return

        command = request["command"]
        match command:
            case LevelDProtocol.Bootstrap.value:
                self._handle_bootstrap(request)

    def _send(self, address: IPv4Address, data: Json) -> None:
        encoded_data = json.dumps(data).encode()
        self._socket.sendto(encoded_data, (address.exploded, self._port))

    @property
    def _port(self) -> Int:
        return LEVEL_D_PORT

    def _handle_bootstrap(self, request: Json) -> None:
        # Get this node's identifier.
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
            ip = IPv4Address(bytes.fromhex(ip))
            if self._level0.join(ip): break

        # Place node info on the DHT.
        info = {
            "pub_key": PubKey(load_pem_public_key(open("_crypt/public_key.pem").read().encode())).bytes.hex(),
            "ip": my_address().exploded,
            "id": this_identifier.hex()
        }
        key_file = f"_crypt/{this_identifier.hex()}.key"
        json.dump(info, open(key_file, "w"))
        self._level0.put(key_file)
