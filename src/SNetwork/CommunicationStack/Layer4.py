from __future__ import annotations

import logging
import os.path
import secrets
import struct
import time
from enum import Enum
from ipaddress import IPv6Address
from threading import Thread

from SNetwork.CommunicationStack.LayerN import LayerN, LayerNProtocol, Connection
from SNetwork.CommunicationStack.Isolation import cross_isolation, strict_isolation
from SNetwork.Config import PORT
from SNetwork.Crypt.AsymmetricKeys import SecKey, PubKey
from SNetwork.Crypt.KEM import KEM
from SNetwork.Crypt.Sign import Signer
from SNetwork.Crypt.Certificate import X509Certificate
from SNetwork.Managers.KeyManager import KeyManager
from SNetwork.Managers.ProfileManager import ProfileManager
from SNetwork.Utils.Types import Bytes, Optional, Dict, List, Json, Int


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
        connect: Initiate a connection to a remote node.
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

    def __init__(self, stack, socket) -> None:
        super().__init__(stack, socket)

        # Get the node identifier and static secret key.
        while not os.path.exists("_crypt/secret_key.pem"): pass
        self._this_identifier = KeyManager.get_info(ProfileManager.CURRENT_HASHED_USERNAME)["identifier"]
        self._this_static_secret_key = KeyManager.get_info(ProfileManager.CURRENT_HASHED_USERNAME)["secret_key"]

        # Store the DHT node and conversation state.
        self._challenges = []
        self._conversations = {}
        logging.debug("Layer 4 Ready")

    @strict_isolation
    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        # Check the request has a command and token, and parse the token.
        if "command" not in request or "token" not in request:
            logging.error(f"Invalid request: {request}")
            return

        # Match the command to the appropriate handler.
        token = bytes.fromhex(request["token"])
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
            case Layer4Protocol.CloseConnection.value if token in self._conversations:
                self._handle_close_connection(address, request)
            case _:
                logging.error(f"Invalid command: {request['command']}")
                logging.error(f"Conversation state: {self._conversations[token].state}")

    @strict_isolation
    def _send(self, connection: Connection, data: Json) -> None:
        # Add the connection token, and send the unencrypted data to the address.
        encoded_data = self._prep_data(connection, data)
        self._socket.sendto(encoded_data, (connection.address.exploded, PORT))

    @cross_isolation(4)
    def connect(self, address: IPv6Address, that_identifier: Bytes) -> Optional[Connection]:
        """
        The "connect" method is called to create a UDP connection to another node in the network. This method handles
        the handshake, and authenticates and encrypts the connection. If the connection is accepted, a Connection object
        is returned, which can be used to send and receive data. Otherwise, None is returned.
        """

        logging.debug(f"Connecting to {address}")

        # Create a unique token for the conversation, allowing for multiple context-free conversations with the same
        # node. The token will be sent with every message, and used as the key for accessing connections.
        token = secrets.token_bytes(32)

        # Generate a new ephemeral key pair and sign the public key using the static secret key.
        this_ephemeral_key_pair = KEM.generate_key_pair()
        this_ephemeral_public_key_signed = Signer.sign(
            my_static_secret_key=self._this_static_secret_key,
            message=this_ephemeral_key_pair.public_key.der,
            their_id=that_identifier)

        # Create the Connection object to track the conversation. It also contains all cryptography-related data used by
        # higher levels in the Communication Stack. Store it against the token in the "conversations" dictionary.
        connection = Connection(
            address=address,
            identifier=that_identifier,
            token=token,
            state=Layer4Protocol.RequestConnection,
            challenge=None,
            ephemeral_public_key=this_ephemeral_key_pair.public_key,
            ephemeral_secret_key=this_ephemeral_key_pair.secret_key,
            e2e_primary_key=None)
        self._conversations[token] = connection

        # Create the JSON request to request a connection. Include the certificate and signed ephemeral public key.
        self._send(connection, {
            "command": Layer4Protocol.RequestConnection.value,
            "certificate": self._this_certificate.der.hex(),
            "ephemeral_public_key": this_ephemeral_key_pair.public_key.der.hex(),
            "ephemeral_public_key_signature": this_ephemeral_public_key_signed.hex()})

        # Wait for the connection to be accepted, rejected or closed, and return a value accordingly.
        while connection.state not in {Layer4Protocol.AcceptConnection, Layer4Protocol.RejectConnection, Layer4Protocol.CloseConnection}:
            pass
        return connection if connection.is_accepted() else None

    @strict_isolation
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
        verification = Signer.verify(
            their_static_public_key=that_static_public_key,
            message=that_ephemeral_public_key.der,
            signature=that_ephemeral_public_key_signature,
            target_id=self._this_identifier)

        if not verification:
            self._send(connection, {
                "command": Layer4Protocol.RejectConnection.value,
                "reason": "Invalid ephemeral public key signature."})
            return

        # Create a challenge for the requesting node to sign, to ensure that it has the private key, and sign it.
        challenge = secrets.token_bytes(24) + struct.pack("!d", time.time())
        signed_challenge = Signer.sign(
            my_static_secret_key=self._this_static_secret_key,
            message=challenge,
            their_id=that_identifier)

        # Send the request and store the conversation state.
        self._conversations[connection.token] = connection
        self._conversations[connection.token].challenge = challenge
        self._send(connection, {
            "command": Layer4Protocol.SignatureChallenge.value,
            "challenge": challenge.hex()})

    @strict_isolation
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
            self._send(connection, {
                "command": Layer4Protocol.CloseConnection.value,
                "reason": f"Invalid challenge: {e}."})
            return

        # Sign the challenge response and send it to the accepting node.
        logging.debug("Signing challenge")
        challenge_response = Signer.sign(
            my_static_secret_key=self._this_static_secret_key,
            message=challenge,
            their_id=connection.identifier)

        # Update the connection information, and store the challenge.
        connection.state = Layer4Protocol.ChallengeResponse
        connection.challenge = challenge
        self._challenges.append(challenge)

        # Send the challenge response.
        self._send(connection, {
            "command": Layer4Protocol.ChallengeResponse.value,
            "challenge_response": challenge_response.hex()})

    @strict_isolation
    def _handle_challenge_response(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received challenge response from {address}")

        # Get the conversation state and the challenge response.
        token = bytes.fromhex(request["token"])
        connection = self._conversations[token]

        # Prepare static keys.
        that_identifier = connection.identifier
        that_static_public_key = self._cached_certificates[that_identifier].public_key

        # Extract the challenge-response from the data, and the challenge from the connection cache.
        challenge = connection.challenge
        challenge_response = bytes.fromhex(request["challenge_response"])

        # Verify the challenge response.
        verification = Signer.verify(
            their_static_public_key=that_static_public_key,
            message=challenge,
            signature=challenge_response,
            target_id=self._this_identifier)

        if not verification:
            self._send(connection, {
                "command": Layer4Protocol.CloseConnection.value,
                "reason": "Invalid challenge response signature."})
            return

        # Create a primary key, and sign it with the static secret key.
        primary_key = secrets.token_bytes(32)
        signed_primary_key = Signer.sign(
            my_static_secret_key=self._this_static_secret_key,
            message=primary_key,
            their_id=that_identifier)

        # Wrap the primary key and its signature inside the KEM.
        kem_wrapped_signed_primary_key = KEM.kem_wrap(
            their_ephemeral_public_key=connection.ephemeral_public_key,
            decapsulated_key=primary_key + signed_primary_key).encapsulated

        # Send the request and update the connection information.
        connection.state = Layer4Protocol.AcceptConnection
        connection.e2e_primary_key = primary_key
        self._send(connection, {
            "command": Layer4Protocol.AcceptConnection.value,
            "kem_primary_key": kem_wrapped_signed_primary_key.hex()})

    @strict_isolation
    def _handle_accept_connection(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received connection acceptance from {address}")

        # Get the conversation state and the challenge response.
        token = bytes.fromhex(request["token"])
        connection = self._conversations[token]

        # Prepare static keys.
        that_identifier = connection.identifier
        that_static_public_key = self._cached_certificates[that_identifier].public_key

        # Decapsulate the key to get the primary key and its signature.
        kem_wrapped_signed_primary_key = bytes.fromhex(request["kem_primary_key"])
        primary_key_and_signature = KEM.kem_unwrap(
            my_ephemeral_secret_key=connection.ephemeral_secret_key,
            encapsulated_key=kem_wrapped_signed_primary_key)
        primary_key, primary_key_signature = primary_key_and_signature.decapsulated[:32], primary_key_and_signature.decapsulated[32:]

        # Verify the signature on the kem wrapped primary key.
        verification = Signer.verify(
            their_static_public_key=that_static_public_key,
            message=primary_key,
            signature=primary_key_signature,
            target_id=self._this_identifier)

        if not verification:
            self._send(connection, {
                "command": Layer4Protocol.CloseConnection.value,
                "reason": "Invalid kem wrapped primary key signature."})
            return

        # Mark the connection as accepted.
        connection.e2e_primary_key = primary_key
        connection.state = Layer4Protocol.AcceptConnection

    @strict_isolation
    def _handle_reject_connection(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received connection rejection from {address}")

        # Close and delete the connection.
        connection = self._conversations[bytes.fromhex(request["token"])]
        connection.state = Layer4Protocol.CloseConnection
        del self._conversations[connection.token]

    @strict_isolation
    def _handle_close_connection(self, address: IPv6Address, request: Json) -> None:
        logging.debug(f"Received connection close from {address}")

        # Close and delete the connection.
        connection = self._conversations[bytes.fromhex(request["token"])]
        connection.state = Layer4Protocol.CloseConnection
        del self._conversations[connection.token]
