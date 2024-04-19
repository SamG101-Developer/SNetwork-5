import json
import os
from enum import Enum
from ipaddress import IPv6Address
from threading import Thread

from src.CommStack.Level0 import Level0
from src.CommStack.LevelN import LevelN, LevelNProtocol, Connection
from src.Crypt.Hash import Hasher, SHA3_256
from src.Crypt.Sign import Signer
from src.Utils.Types import Json, Int, Bool

DIRECTORY_IP = IPv6Address("fe80::399:3723:1f1:ea97")


class LevelDProtocol(Enum, LevelNProtocol):
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
            "command": LevelDProtocol.JoinNetwork.value,
            "public_key": this_static_public_key,
            "identifier": this_identifier.hex()}

        # Send the request to the directory node.
        connection = Connection(DIRECTORY_IP, this_identifier, os.urandom(32), LevelDProtocol.JoinNetwork, None, None, None, None)
        self._send(connection, request)

    def _listen(self) -> None:
        ...

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        if "command" not in request:
            return

        command = request["command"]
        match command:
            case LevelDProtocol.Bootstrap.value:
                self._handle_bootstrap(request)

    def _send(self, connection: Connection, data: Json) -> None:
        encoded_data = json.dumps(data).encode()
        self._socket.sendto(encoded_data, (connection.address.exploded, self._port))

    @property
    def _port(self) -> Int:
        return 40003

    def _handle_bootstrap(self, request: Json) -> None:
        # Ge this node's identifier.
        this_identifier = Hasher.hash(open("_crypt/public_key.pem").read().encode(), SHA3_256())

        # Add the node to the DHT.
        node_ip_addresses = request["node_ip_addresses"]
        for ip in node_ip_addresses:
            ip = IPv6Address(ip)
            if self._level0.join(ip): break

        # Place node info on the DHT.
        key_file = f"_crypt/{this_identifier.hex()}.pem"
        open(key_file, "w").write(open("_crypt/public_key.pem").read())
        self._level0.put(key_file)
