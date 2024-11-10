import logging
import secrets
from enum import Enum
from ipaddress import IPv6Address

from SNetwork.CommunicationStack.LayerN import Connection, LayerN, LayerNProtocol
from SNetwork.Config import DIRECTORY_IP, DIRECTORY_IDENTIFIER
from SNetwork.Crypt.AsymmetricKeys import KeyPair
from SNetwork.Crypt.Certificate import X509CertificateSigningRequest, X509Certificate
from SNetwork.Crypt.Hash import Hasher, SHA3_256
from SNetwork.Managers.KeyManager import KeyManager
from SNetwork.Crypt.Sign import Signer
from SNetwork.Utils.Types import Json, Bool, Optional, Bytes


class LayerDProtocol(LayerNProtocol, Enum):
    CertificateRequest = 0x01
    CertificateResponse = 0x02
    InvalidCertificateRequest = 0x03


class LayerD(LayerN):
    """
    Layer D isn't part of the connection stack, but is used for communicating to the directory service. This is used for
    bootstrapping and getting node information when the distributed hash table fails to provide the information. As it
    follows the same API as other layers, it is designated as an unnumbered layer.

    The directory service will use this layer too, and no other stack, to talk back to the nodes, for things such as
    certificate generation, etc.
    """

    _this_identifier: Optional[bytes]
    _this_static_key_pair: Optional[KeyPair]
    _is_directory_service: Bool
    _waiting_for_certificate: Bool

    def __init__(self, stack, socket, is_directory_service: Bool, this_identifier: Bytes, this_static_key_pair: Optional[KeyPair] = None) -> None:
        super().__init__(stack, socket)

        assert bool(is_directory_service) is bool(this_static_key_pair)
        self._this_identifier = this_identifier
        self._this_static_key_pair = this_static_key_pair
        self._is_directory_service = is_directory_service
        self._waiting_for_certificate = False

        # Start listening on the socket for this layer.
        logging.debug("Layer D Ready")

    def join_network(self, this_unique_identifier: bytes) -> None:
        # Create a temporary, unencrypted connection to the directory service (first time: cant use L4).
        temp_connection = Connection(address=DIRECTORY_IP, identifier=DIRECTORY_IDENTIFIER, token=secrets.token_bytes(32))

        # Create an asymmetric key pair, and an associated certificate.
        this_static_key_pair = Signer.generate_key_pair()
        this_certificate_request = X509CertificateSigningRequest.from_attributes(this_unique_identifier, this_static_key_pair.secret_key)

        # Package the information into a request for the directory service.
        self._waiting_for_certificate = True
        self._send(temp_connection, {
            "protocol": LayerDProtocol.CertificateRequest.value,
            "identifier": this_unique_identifier,
            "public_key": this_static_key_pair.public_key.der,
            "certificate": this_certificate_request.der})

    def _handle_certificate_request(self, address: IPv6Address, request: Json) -> None:
        # Extract metadata from the request.
        identifier = bytes.fromhex(request["identifier"])
        public_key = bytes.fromhex(request["public_key"])
        certificate_request = X509CertificateSigningRequest.from_der(bytes.fromhex(request["certificate"]))

        # Create the temporary connection (1-use connection, so don't cache it).
        temp_connection = Connection(address=address, identifier=request["identifier"], token=request["token"])

        if Hasher.hash(public_key, SHA3_256()) != identifier:
            self._send(temp_connection, {
                "protocol": LayerDProtocol.InvalidCertificateRequest.value,
                "reason": "Public key / identifier mismatch."})

        # Create the signed certificate, and send it back to the requester.
        certificate = X509Certificate.from_request(certificate_request, self._this_static_key_pair.secret_key)
        self._send(temp_connection, {
            "protocol": LayerDProtocol.CertificateResponse.value,
            "certificate": certificate.der})

        # Todo: Include some bootstrapping nodes.

    def _handle_certificate_response(self, address: IPv6Address, request: Json) -> None:
        # Extract the certificate from the request.
        certificate = X509Certificate.from_der(bytes.fromhex(request["certificate"]))

        # Ensure it was not tampered with (check the public key and identifier on it)
        if certificate.subject != self._this_identifier:
            logging.error("Invalid certificate identifier.")
            return
        if certificate.public_key.der != self._this_static_key_pair.public_key.der:
            logging.error("Invalid certificate public key.")
            return

        # Store the certificate and other information in the key store.
        KeyManager.set_info(
            identifier=self._this_identifier,
            secret_key=self._this_static_key_pair.secret_key,
            public_key=self._this_static_key_pair.public_key,
            certificate=certificate)

        # Todo: Cache node list and exchange with (some of?) them.

    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        # Check the request has a command and token.
        if "command" not in request or "token" not in request:
            logging.error(f"Invalid request: {request}")
            return

        match request["command"]:
            case LayerDProtocol.CertificateRequest.value:
                self._handle_certificate_request(address, request)
            case LayerDProtocol.CertificateResponse.value if self._waiting_for_certificate:
                self._handle_certificate_response(address, request)

    def _send(self, connection: Connection, data: Json) -> None:
        pass
