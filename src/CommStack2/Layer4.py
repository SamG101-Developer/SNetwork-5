from __future__ import annotations

from ipaddress import IPv6Address
from enum import Enum
from threading import Thread
import json, logging, os, struct, time

from src.Crypt.AsymmetricKeys import SecKey, PubKey
from src.Crypt.KEM import KEM
from src.Crypt.KeyManager import KeyManager
from src.Crypt.Sign import Signer
from src.Crypt.Certificate import X509Certificate
from src.CommStack2.LayerN import LayerN, LayerNProtocol, Connection
from src.Utils.Types import Bytes, Optional, Dict, List, Json, Int
from src.CONFIG import LAYER_4_PORT, DEFAULT_IPV6


class Layer4Protocol(LayerNProtocol, Enum):
    RequestConnection  = 0x00
    SignatureChallenge = 0x01
    ChallengeResponse  = 0x02
    AcceptConnection   = 0x03
    RejectConnection   = 0x04
    CloseConnection    = 0x05


class Layer4(LayerN):
    """
    Layer 4 of the Communication Stack is the "Connection Layer". This layer is responsible for establishing secure
    connections between nodes in the network. It uses a combination of asymmetric keys, digital signatures, and key
    exchange mechanisms to ensure that the connection is secure and authenticated.

    Data sent in this layer is unencrypted, but authenticated. Once a connection is established, the end-to-end
    encryption is handled by the higher layers of the stack, specifically Layer 3 (DHT) and Layer 2 (Routing).

    Attributes:
        _this_identifier: The identifier of this node.
        _this_static_secret_key: The static secret key of this node.
        _this_certificate: The X.509 certificate of this node.
        _challenges: A list of challenges this node has received.
        _conversations: A dictionary of active conversations with other nodes.
        _cached_certificates: A dictionary of cached certificates for other nodes.

    Methods:
        connect: Initiates a connection to a remote node.
        _listen: Listens for incoming raw requests on the insecure socket.
        _handle_command: Handles incoming commands from other nodes.
        _send: Sends unencrypted data to a remote node.
        _handle_connection_request: Handles a connection request from a remote node.
        _handle_signature_challenge: Handles a signature challenge from a remote node.
        _handle_challenge_response: Handles a challenge response from a remote node.
        _handle_accept_connection: Handles an accepted connection from a remote node.
        _handle_reject_connection: Handles a rejected connection from a remote node.
        _handle_close_connection: Handles a closed connection from a remote node.
    """

    _this_identifier: Bytes
    _this_static_secret_key: SecKey
    _this_certificate: X509Certificate
    _challenges: List[Bytes]
    _conversations: Dict[Bytes, Connection]
    _cached_certificates: Dict[Bytes, X509Certificate]

    def __init__(self) -> None:
        super().__init__()

        # Get the node identifier and static secret key.
        while not os.path.exists("_crypt/secret_key.pem"): pass
        self._this_identifier = KeyManager.get_identifier()
        self._this_static_secret_key = KeyManager.get_static_secret_key()

        # Store the DHT node and conversation state.
        self._challenges = []
        self._conversations = {}

        # Start listening on both sockets.
        Thread(target=self._listen).start()
        logging.debug("Layer 4 Ready")

    def _listen(self) -> None:
        # Bind the insecure socket to port 40000.
        self._socket.bind((DEFAULT_IPV6, self._port))

        # Listen for incoming raw requests, and handle them in a new thread.
        while True:
            data, address = self._socket.recvfrom(4096)
            request = json.loads(data)
            Thread(target=self._handle_command, args=(IPv6Address(address[0]), request)).start()

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        # Check the request has a command and token, and parse the token.
        if "command" not in request or "token" not in request:
            logging.error(f"Invalid request: {request}")
            return
        token = bytes.fromhex(request["token"])

        # Match the command to the appropriate handler.
        match request["command"]:
            case Layer4Protocol.RequestConnection.value:
                self._handle_connection_request(address, request)
            case Layer4Protocol.SignatureChallenge.value if self._conversations[token].state == Layer4Protocol.RequestConnection:
                self._handle_signature_challenge(address, request)
            case Layer4Protocol.ChallengeResponse.value if self._conversations[token].state == Layer4Protocol.SignatureChallenge:
                self._handle_challenge_response(address, request)
            case Layer4Protocol.AcceptConnection.value if self._conversations[token].state == Layer4Protocol.ChallengeResponse:
                self._handle_accept_connection(address, request)
            case Layer4Protocol.RejectConnection.value if self._conversations[token].state == Layer4Protocol.RequestConnection:
                self._handle_reject_connection(address, request)
            case Layer4Protocol.CloseConnection.value:
                self._handle_close_connection(address, request)
            case _:
                logging.error(f"Invalid command: {request['command']}")
                logging.error(f"Conversation state: {self._conversations[token].state}")

    def _send(self, connection: Connection, data: Json) -> None:
        # Send the unencrypted data to the address.
        encoded_data = json.dumps(data).encode()
        self._socket.sendto(encoded_data, (connection.address.exploded, self._port))

    @property
    def _port(self) -> Int:
        # Get the port from the configuration.
        return LAYER_4_PORT

    def connect(self, address: IPv6Address, that_identifier: Bytes) -> Optional[Connection]:
        logging.debug(f"Connecting to {address}")

        # Create a unique token for the conversation.
        token = os.urandom(32)

        # Prepare static and ephemeral keys.
        this_ephemeral_key_pair = KEM.generate_key_pair()
        this_ephemeral_public_key_signed = Signer.sign(self._this_static_secret_key, this_ephemeral_key_pair.public_key.der)
        logging.debug(f"This ephemeral public key: {this_ephemeral_key_pair.public_key.der.hex()}")

        # Create the Connection object to track the conversation.
        connection = Connection(
            address=address,
            identifier=that_identifier,
            token=token,
            state=Layer4Protocol.RequestConnection,
            challenge=None,
            ephemeral_public_key=this_ephemeral_key_pair.public_key,
            ephemeral_secret_key=this_ephemeral_key_pair.secret_key,
            e2e_primary_key=None)

        # Create the JSON request to request a connection.
        request = {
            "command": Layer4Protocol.RequestConnection.value,
            "token": token.hex(),
            "certificate": self._this_certificate.der.hex(),
            "ephemeral_public_key": this_ephemeral_key_pair.public_key.der.hex(),
            "ephemeral_public_key_signature": this_ephemeral_public_key_signed.hex()}

        # Send the request and store the conversation state.
        self._conversations[token] = connection
        self._send(connection, request)

        # Wait for the connection to be accepted or rejected.
        while connection.state not in {Layer4Protocol.AcceptConnection, Layer4Protocol.RejectConnection, Layer4Protocol.CloseConnection}:
            pass
        return connection if connection.state == Layer4Protocol.AcceptConnection else None

    def _handle_connection_request(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received connection request from {address}")

        # Extract the certificate and ephemeral public key from the request.
        token = bytes.fromhex(request["token"])
        that_certificate = X509Certificate.from_der(bytes.fromhex(request["certificate"]))
        that_identifier = that_certificate.subject
        that_static_public_key = that_certificate.public_key
        that_ephemeral_public_key = PubKey.from_der(bytes.fromhex(request["ephemeral_public_key"]))
        that_ephemeral_public_key_signature = bytes.fromhex(request["ephemeral_public_key_signature"])
        self._cached_certificates[that_identifier] = that_certificate

        logging.debug(f"Their ephemeral public key: {that_ephemeral_public_key.der.hex()}")

        # Create the Connection object to track the conversation.
        connection = Connection(
            address=address,
            identifier=that_identifier,
            token=token,
            state=Layer4Protocol.SignatureChallenge,
            challenge=None,
            ephemeral_public_key=that_ephemeral_public_key,
            ephemeral_secret_key=None,
            e2e_primary_key=None)

        # Verify the signed ephemeral public key, and reject the connection if there's an invalid signature.
        if not Signer.verify(that_static_public_key, that_ephemeral_public_key.der, that_ephemeral_public_key_signature):
            response = {
                "command": Layer4Protocol.RejectConnection.value,
                "token": token.hex(),
                "reason": "Invalid ephemeral public key signature."}
            self._send(connection, response)
            return

        # Send a signed challenge for the requesting node to sign, to ensure that it has the private key.
        challenge = os.urandom(24) + struct.pack("!d", time.time())
        challenge_signed = Signer.sign(self._this_static_secret_key, challenge)
        response = {
            "command": Layer4Protocol.SignatureChallenge.value,
            "token": token.hex(),
            "challenge": challenge.hex()}

        # Send the request and store the conversation state.
        self._conversations[connection.token] = connection
        self._conversations[connection.token].challenge = challenge
        self._send(connection, response)

    def _handle_signature_challenge(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received signature challenge from {address}")

        # Get the conversation state and the challenge response.
        token = bytes.fromhex(request["token"])
        challenge = bytes.fromhex(request["challenge"])
        connection = self._conversations[token]
        that_static_public_key = self._cached_certificates[connection.identifier].public_key

        # Ensure this challenge hasn't been used this session, and the challenge isn't stale.
        try:
            assert challenge not in self._challenges, "Challenge has already been used."
            assert struct.unpack("!d", challenge[-8:])[0] > time.time() - 60, "Challenge is stale."
        except AssertionError as e:
            response = {
                "command": Layer4Protocol.CloseConnection.value,
                "token": token.hex(),
                "reason": f"Invalid challenge: {e}."}
            self._send(connection, response)
            return

        # Sign the challenge response and send it to the accepting node.
        logging.debug("Signing challenge")
        challenge_response = Signer.sign(self._this_static_secret_key, challenge)
        response = {
            "command": Layer4Protocol.ChallengeResponse.value,
            "token": token.hex(),
            "challenge_response": challenge_response.hex()}

        # Send the request and store the conversation state.
        connection.state = Layer4Protocol.ChallengeResponse
        connection.challenge = challenge
        self._challenges.append(challenge)
        self._send(connection, response)

    def _handle_challenge_response(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received challenge response from {address}")

        # Get the conversation state and the challenge response.
        token = bytes.fromhex(request["token"])
        connection = self._conversations[token]

        # Prepare static keys.
        that_identifier = connection.identifier
        that_static_public_key = self._cached_certificates[that_identifier].public_key

        # Verify the challenge response.
        challenge = connection.challenge
        challenge_response = bytes.fromhex(request["challenge_response"])
        logging.debug("Verifying challenge response")
        if not Signer.verify(that_static_public_key, challenge, challenge_response):
            response = {
                "command": Layer4Protocol.CloseConnection.value,
                "token": token.hex(),
                "reason": "Invalid challenge response signature."}
            self._send(connection, response)
            return

        # Create the response to accept the connection, and wrap a primary key for end-to-end encryption.
        primary_key = os.urandom(32)
        kem_wrapped_primary_key_signed = Signer.sign(self._this_static_secret_key, primary_key)
        kem_wrapped_primary_key = KEM.kem_wrap(connection.ephemeral_public_key, primary_key + kem_wrapped_primary_key_signed).encapsulated
        response = {
            "command": Layer4Protocol.AcceptConnection.value,
            "token": request["token"],
            "kem_primary_key": kem_wrapped_primary_key.hex()}

        # Send the request and store the conversation state.
        connection.state = Layer4Protocol.AcceptConnection
        connection.e2e_primary_key = primary_key
        self._send(connection, response)

    def _handle_accept_connection(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received connection acceptance from {address}")

        # Get the conversation state and the challenge response.
        token = bytes.fromhex(request["token"])
        connection = self._conversations[token]

        # Prepare static keys.
        that_identifier = connection.identifier
        that_static_public_key = self._cached_certificates[that_identifier].public_key

        # Decapsulate the key to get the primary key and its signature.
        kem_wrapped_primary_key = bytes.fromhex(request["kem_primary_key"])
        primary_key_and_signature = KEM.kem_unwrap(connection.ephemeral_secret_key, kem_wrapped_primary_key)
        primary_key, primary_key_signature = primary_key_and_signature.decapsulated[:32], primary_key_and_signature.decapsulated[32:]

        # Verify the signature on the kem wrapped primary key.
        if not Signer.verify(that_static_public_key, primary_key, primary_key_signature):
            response = {
                "command": Layer4Protocol.CloseConnection.value,
                "token": token.hex(),
                "reason": "Invalid kem wrapped primary key signature."}
            self._send(connection, response)
            return

        # Mark the connection as accepted.
        connection.e2e_primary_key = primary_key
        connection.state = Layer4Protocol.AcceptConnection

    def _handle_reject_connection(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received connection rejection from {address}")

        # Close and delete the connection.
        connection = self._conversations[bytes.fromhex(request["token"])]
        connection.state = Layer4Protocol.CloseConnection
        del self._conversations[connection.token]

    def _handle_close_connection(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received connection close from {address}")

        # Close and delete the connection.
        connection = self._conversations[bytes.fromhex(request["token"])]
        connection.state = Layer4Protocol.CloseConnection
        del self._conversations[connection.token]
