from __future__ import annotations

from pqcrypto.sign import dilithium4

from SNetwork.Config import MESSAGE_SIGNATURE_TOLERANCE
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.Timestamp import Timestamp
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Bool, Bytes, Int


class QuantumSign:
    LOGGER = isolated_logger(LoggerHandlers.CRYPT)
    HASH_ALGORITHM = HashAlgorithm.SHA3_256

    @staticmethod
    def generate_key_pair() -> AsymmetricKeyPair:
        public_key, secret_key = dilithium4.generate_keypair()
        return AsymmetricKeyPair(public_key=public_key, secret_key=secret_key)

    @staticmethod
    def sign(*, secret_key: Bytes, message: Bytes, target_id: Bytes) -> Bytes:
        # Add the target identifier and timestamp to the message and hash it.
        message += target_id + Timestamp.generate_time_stamp()
        hashed_message = Hasher.hash(data=message, algorithm=QuantumSign.HASH_ALGORITHM)

        # Sign the hashed extended message and return the signature.
        signature = dilithium4.sign(secret_key, hashed_message)
        return signature

    @staticmethod
    def verify(*, public_key: Bytes, message: Bytes, signature: Bytes, target_id: Bytes, tolerance: Int = MESSAGE_SIGNATURE_TOLERANCE) -> Bool:
        # Check if the timestamp is valid.
        timestamp = message[-8:]
        if not Timestamp.check_time_stamp(message[-8:]):
            QuantumSign.LOGGER.error("Stale signature timestamp.")
            return False

        # Check if the ID matches the target ID.
        candidate_id = message[-QuantumSign.HASH_ALGORITHM.digest_size - 8:-8]
        if candidate_id != target_id:
            QuantumSign.LOGGER.error(f"Invalid target ID: {candidate_id}.")
            return False

        # Verify the signature against the message.
        if dilithium4.verify(message, signature, public_key):
            QuantumSign.LOGGER.error("Invalid signature.")
            return False

        # If all checks pass, return True.
        return True


__all__ = ["QuantumSign"]
