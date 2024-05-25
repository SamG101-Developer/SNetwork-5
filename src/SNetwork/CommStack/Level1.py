"""
The Level1 layer of the stack is used to establish connections between nodes on the network. It operates over an
insecure socket. Once the secure connection is established, the secure socket (with e2e encryption) is used to send and
receive data. This is done in Layer2.
"""

from __future__ import annotations

import logging
from ipaddress import IPv4Address
from enum import Enum
from threading import Thread
import json, os, struct, time

from src.Crypt.AsymmetricKeys import SecKey, PubKey
from src.Crypt.KEM import KEM
from src.Crypt.KeyManager import KeyManager
from src.Crypt.Sign import Signer
from src.CommStack.LevelN import LevelN, LevelNProtocol, Connection
from src.CommStack.Level0 import Level0
from src.Utils.Types import Bytes, Optional, Dict, List, Json, Int
from src.CONFIG import LEVEL_1_PORT


class Level1Protocol(LevelNProtocol, Enum):
    RequestConnection  = 0x00
    SignatureChallenge = 0x01
    ChallengeResponse  = 0x02
    AcceptConnection   = 0x03
    RejectConnection   = 0x04
    CloseConnection    = 0x05


class Level1(LevelN):
    _level0: Level0
    _challenges: List[Bytes]
    _conversations: Dict[Bytes, Connection]

    _this_identifier: Bytes
    _this_static_secret_key: SecKey

    def __init__(self, level0: Level0) -> None:
        super().__init__()

        # Store the DHT node and conversation state.
        self._level0 = level0
        self._challenges = []
        self._conversations = {}

        # Get the node identifier and static secret key.
        while not os.path.exists("_crypt/secret_key.pem"):
            pass
        self._this_identifier = KeyManager.get_identifier()
        self._this_static_secret_key = KeyManager.get_static_secret_key()

        # Start listening on both sockets.
        Thread(target=self._listen).start()

        logging.debug("Layer 1 Ready")

    def _listen(self) -> None:
        # Bind the insecure socket to port 40000.
        self._socket.bind(("", self._port))

        # Listen for incoming raw requests, and handle them in a new thread.
        while True:
            data, address = self._socket.recvfrom(4096)
            request = json.loads(data)
            Thread(target=self._handle_command, args=(IPv4Address(address[0]), request)).start()

    def _handle_command(self, address: IPv4Address, request: Json) -> None:
        # Check the request has a command and token, and parse the token.
        if "command" not in request or "token" not in request:
            logging.error(f"Invalid request: {request}")
            return
        token = bytes.fromhex(request["token"])

        # Match the command to the appropriate handler.
        match request["command"]:
            case Level1Protocol.RequestConnection.value:
                self._handle_connection_request(address, request)
            case Level1Protocol.SignatureChallenge.value if self._conversations[token].state == Level1Protocol.RequestConnection:
                self._handle_signature_challenge(address, request)
            case Level1Protocol.ChallengeResponse.value if self._conversations[token].state == Level1Protocol.SignatureChallenge:
                self._handle_challenge_response(address, request)
            case Level1Protocol.AcceptConnection.value if self._conversations[token].state == Level1Protocol.ChallengeResponse:
                self._handle_accept_connection(address, request)
            case Level1Protocol.RejectConnection.value if self._conversations[token].state == Level1Protocol.RequestConnection:
                self._handle_reject_connection(address, request)
            case Level1Protocol.CloseConnection.value:
                self._handle_close_connection(address, request)
            case _:
                logging.error(f"Unknown command: {request['command']}")
                logging.error(f"Conversation state: {self._conversations[token].state}")

    def _send(self, connection: Connection, data: Json) -> None:
        # Send the unencrypted data to the address.
        encoded_data = json.dumps(data).encode()
        self._socket.sendto(encoded_data, (connection.address.exploded, self._port))

    @property
    def _port(self) -> Int:
        # Get the port from the configuration.
        return LEVEL_1_PORT

    def connect(self, address: IPv4Address, that_identifier: Bytes, token: Bytes = b"") -> Optional[Connection]:
        logging.debug(f"Connecting to {address}")

        token = token or os.urandom(32)

        # Prepare static and ephemeral keys.
        this_ephemeral_key_pair = KEM.generate_key_pair()
        this_ephemeral_public_key_signed = Signer.sign(self._this_static_secret_key, this_ephemeral_key_pair.public_key.der)
        logging.debug(f"This ephemeral public key: {this_ephemeral_key_pair.public_key.der.hex()}")

        # Create the handshake request.
        request = {
            "command": Level1Protocol.RequestConnection.value,
            "token": token.hex(),
            "identifier": self._this_identifier.hex(),
            "ephemeral_public_key": this_ephemeral_key_pair.public_key.der.hex(),
            "ephemeral_public_key_signature": this_ephemeral_public_key_signed.hex()}

        # Send the request and store the conversation state.
        connection = Connection(address, that_identifier, token, Level1Protocol.RequestConnection, None, this_ephemeral_key_pair.public_key, this_ephemeral_key_pair.secret_key, None)
        self._conversations[token] = connection
        self._send(connection, request)

        # Wait for the connection to be accepted or rejected.
        while connection.state not in {Level1Protocol.AcceptConnection, Level1Protocol.RejectConnection, Level1Protocol.CloseConnection}:
            pass
        return connection if connection.state == Level1Protocol.AcceptConnection else None

    def _handle_connection_request(self, address: IPv4Address, request: Json) -> None:
        logging.debug(f"Received connection request from {address}")

        # Get the identifier and key information, and get the certificate from the DHT.
        that_identifier = bytes.fromhex(request["identifier"])
        that_ephemeral_public_key = PubKey.from_der(bytes.fromhex(request["ephemeral_public_key"]))
        that_ephemeral_public_key_signature = bytes.fromhex(request["ephemeral_public_key_signature"])
        that_static_public_key = PubKey.from_der(bytes.fromhex(json.loads(self._level0.get(f"{that_identifier.hex()}.key"))["pub_key"]))
        logging.debug(f"Their ephemeral public key: {that_ephemeral_public_key.der.hex()}")

        # Create the connection
        connection = Connection(address, that_identifier, bytes.fromhex(request["token"]), Level1Protocol.SignatureChallenge, None, that_ephemeral_public_key, None, None)

        # Verify the signed ephemeral public key, and reject the connection if there's an invalid signature.
        if not Signer.verify(that_static_public_key, that_ephemeral_public_key.der, that_ephemeral_public_key_signature):
            response = {
                "command": Level1Protocol.RejectConnection.value,
                "token": request["token"],
                "reason": "Invalid ephemeral public key signature."}
            self._send(connection, response)
            return

        # Send a signed challenge for the requesting node to sign, to ensure that it has the private key.
        challenge = os.urandom(24) + struct.pack("!d", time.time())
        challenge_signed = Signer.sign(self._this_static_secret_key, challenge)
        response = {
            "command": Level1Protocol.SignatureChallenge.value,
            "token": request["token"],
            "challenge": challenge.hex(),
            "challenge_signature": challenge_signed.hex()}

        # Send the request and store the conversation state.
        self._conversations[connection.token] = connection
        self._conversations[connection.token].challenge = challenge
        self._send(connection, response)

    def _handle_signature_challenge(self, address: IPv4Address, request: Json) -> None:
        logging.debug(f"Received signature challenge from {address}")

        # Get the conversation state and the challenge response.
        token = bytes.fromhex(request["token"])
        connection = self._conversations[token]
        that_static_public_key = PubKey.from_der(bytes.fromhex(json.loads(self._level0.get(f"{connection.identifier.hex()}.key"))["pub_key"]))

        # Verify the challenge received from the accepting node.
        signed_challenge = bytes.fromhex(request["challenge_signature"])
        challenge = bytes.fromhex(request["challenge"])
        logging.debug("Verifying challenge")
        if not Signer.verify(that_static_public_key, challenge, signed_challenge):
            response = {
                "command": Level1Protocol.CloseConnection.value,
                "token": request["token"],
                "reason": "Invalid challenge signature."}
            self._send(connection, response)
            return

        # Ensure this challenge hasn't been used this session, and the time is somewhat recent.
        try:
            assert challenge not in self._challenges, "Challenge has already been used."
            assert struct.unpack("!d", challenge[-8:])[0] > time.time() - 60, "Challenge is stale."
        except AssertionError:
            response = {
                "command": Level1Protocol.CloseConnection.value,
                "token": request["token"],
                "reason": "Invalid challenge."}
            self._send(connection, response)
            return

        # Sign the challenge response and send it to the accepting node.
        logging.debug("Signing challenge")
        challenge_response = Signer.sign(self._this_static_secret_key, challenge)
        response = {
            "command": Level1Protocol.ChallengeResponse.value,
            "token": request["token"],
            "challenge_response": challenge_response.hex()}

        # Send the request and store the conversation state.
        connection.state = Level1Protocol.ChallengeResponse
        connection.challenge = challenge
        self._challenges.append(challenge)
        self._send(connection, response)

    def _handle_challenge_response(self, address: IPv4Address, request: Json) -> None:
        logging.debug(f"Received challenge response from {address}")

        # Get the conversation state and the challenge response.
        token = bytes.fromhex(request["token"])
        connection = self._conversations[token]

        # Prepare static keys.
        that_identifier = connection.identifier
        that_static_public_key = PubKey.from_der(bytes.fromhex(json.loads(self._level0.get(f"{that_identifier.hex()}.key"))["pub_key"]))

        # Verify the challenge response.
        challenge = connection.challenge
        challenge_response = bytes.fromhex(request["challenge_response"])
        logging.debug("Verifying challenge response")
        if not Signer.verify(that_static_public_key, challenge, challenge_response):
            response = {
                "command": Level1Protocol.CloseConnection.value,
                "token": request["token"],
                "reason": "Invalid challenge response signature."}
            self._send(connection, response)
            return

        # Create the response to accept the connection, and wrap a master key for end-to-end encryption.
        logging.debug("Wrapping master key")
        master_key = os.urandom(32)
        logging.debug(f"Master key: {master_key.hex()} ({len(master_key)} bytes)")
        kem_wrapped_master_key = KEM.kem_wrap(connection.ephemeral_public_key, master_key).encapsulated
        logging.debug(f"Wrapped master key: {kem_wrapped_master_key.hex()} ({len(kem_wrapped_master_key)} bytes)")
        kem_wrapped_master_key_signed = Signer.sign(self._this_static_secret_key, kem_wrapped_master_key)
        response = {
            "command": Level1Protocol.AcceptConnection.value,
            "token": request["token"],
            "kem_master_key": kem_wrapped_master_key.hex(),
            "kem_master_key_signature": kem_wrapped_master_key_signed.hex()}

        # Send the request and store the conversation state.
        connection.state = Level1Protocol.AcceptConnection
        connection.e2e_master_key = master_key
        self._send(connection, response)

    def _handle_accept_connection(self, address: IPv4Address, request: Json) -> None:
        logging.debug(f"Received connection acceptance from {address}")

        # Get the conversation state and the challenge response.
        token = bytes.fromhex(request["token"])
        connection = self._conversations[token]

        # Prepare static keys.
        that_identifier = connection.identifier
        that_static_public_key = PubKey.from_der(bytes.fromhex(json.loads(self._level0.get(f"{that_identifier.hex()}.key"))["pub_key"]))

        # Verify the signature on the kem wrapped master key.
        kem_wrapped_master_key = bytes.fromhex(request["kem_master_key"])
        kem_wrapped_master_key_signature = bytes.fromhex(request["kem_master_key_signature"])
        if not Signer.verify(that_static_public_key, kem_wrapped_master_key, kem_wrapped_master_key_signature):
            response = {
                "command": Level1Protocol.CloseConnection.value,
                "token": request["token"],
                "reason": "Invalid kem wrapped master key signature."}
            self._send(connection, response)
            return

        # Unwrap the master key and store it.
        logging.debug(f"Wrapped master key: {kem_wrapped_master_key.hex()} ({len(kem_wrapped_master_key)} bytes)")
        master_key = KEM.kem_unwrap(connection.ephemeral_secret_key, kem_wrapped_master_key).decapsulated
        logging.debug(f"Master key: {master_key.hex()} ({len(master_key)} bytes)")

        # Mark the connection as accepted.
        connection.e2e_master_key = master_key
        connection.state = Level1Protocol.AcceptConnection

    def _handle_reject_connection(self, address: IPv4Address, request: Json) -> None:
        logging.debug(f"Received connection rejection from {address}")

        # Close and delete the connection.
        connection = self._conversations[bytes.fromhex(request["token"])]
        connection.state = Level1Protocol.CloseConnection
        del self._conversations[connection.token]

    def _handle_close_connection(self, address: IPv4Address, request: Json) -> None:
        logging.debug(f"Received connection close from {address}")

        # Close and delete the connection.
        connection = self._conversations[bytes.fromhex(request["token"])]
        connection.state = Level1Protocol.CloseConnection
        del self._conversations[connection.token]