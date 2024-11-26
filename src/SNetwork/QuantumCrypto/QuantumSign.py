from __future__ import annotations
from dataclasses import dataclass
import pickle

from cryptography.hazmat.primitives.constant_time import bytes_eq
from pqcrypto.sign import dilithium4

from SNetwork.Config import MESSAGE_SIGNATURE_TOLERANCE
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.Timestamp import Timestamp
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Bool, Bytes, Int, Tuple


@dataclass(kw_only=True)
class SignedMessagePair:
    extended_message: Bytes
    signature: Bytes


class QuantumSign:
    LOGGER = isolated_logger(LoggerHandlers.CRYPT)
    HASH_ALGORITHM = HashAlgorithm.SHA3_256
    HASH_DIGEST_SIZE = HASH_ALGORITHM().digest_size

    @staticmethod
    def generate_key_pair() -> AsymmetricKeyPair:
        public_key, secret_key = dilithium4.generate_keypair()
        return AsymmetricKeyPair(public_key=public_key, secret_key=secret_key)

    @staticmethod
    def sign(*, skey: Bytes, msg: Bytes, id_: Bytes) -> SignedMessagePair:
        # Add the target identifier and timestamp to the message and hash it.
        timestamp = Timestamp.generate_time_stamp()
        extended_message = pickle.dumps((msg, timestamp, id_))
        hashed_message = Hasher.hash(data=extended_message, algorithm=QuantumSign.HASH_ALGORITHM)

        # Sign the hashed extended message and return the signature.
        signature = dilithium4.sign(skey, hashed_message)
        return SignedMessagePair(extended_message=extended_message, signature=signature)

    @staticmethod
    def verify(*, pkey: Bytes, sig: SignedMessagePair, id_: Bytes, tolerance: Int = MESSAGE_SIGNATURE_TOLERANCE) -> Bool:
        _, timestamp, recipient_id = pickle.loads(sig.extended_message)

        # Check if the timestamp is valid.
        if not Timestamp.check_time_stamp(timestamp):
            QuantumSign.LOGGER.error("Stale signature timestamp.")
            return False

        # Check if the ID matches the target ID.
        if not bytes_eq(recipient_id, id_):
            QuantumSign.LOGGER.error(f"Invalid target ID: {recipient_id}.")
            return False

        # Verify the signature against the message.
        hashed_message = Hasher.hash(data=sig.extended_message, algorithm=QuantumSign.HASH_ALGORITHM)
        if not dilithium4.verify(pkey, hashed_message, sig.signature):
            QuantumSign.LOGGER.error("Invalid signature.")
            return False

        # If all checks pass, return True.
        return True


__all__ = ["QuantumSign"]
