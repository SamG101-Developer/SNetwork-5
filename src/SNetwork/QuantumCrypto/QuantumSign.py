from __future__ import annotations
from dataclasses import dataclass
import pickle

from cryptography.hazmat.primitives.constant_time import bytes_eq
from pqcrypto.sign import dilithium4

from SNetwork.Config import TOLERANCE_MESSAGE_SIGNATURE
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
    def sign(*, skey: Bytes, msg: Bytes, aad: Bytes) -> SignedMessagePair:
        # Add the target identifier and timestamp to the message and hash it.
        timestamp = Timestamp.generate_time_stamp()
        extended_message = pickle.dumps((msg, timestamp, aad))
        hashed_message = Hasher.hash(data=extended_message, algorithm=QuantumSign.HASH_ALGORITHM)

        # Sign the hashed extended message and return the signature.
        signature = dilithium4.sign(skey, hashed_message)
        return SignedMessagePair(extended_message=extended_message, signature=signature)

    @staticmethod
    def verify(*, pkey: Bytes, sig: SignedMessagePair, raw: Bytes = None, aad: Bytes = b"", tolerance: Int = TOLERANCE_MESSAGE_SIGNATURE) -> Bool:
        """
        Verify the signature against the message.

        Args:
            pkey: The public key to verify the signature with.
            sig: The signature to verify.
            raw: The raw message that the signature should match (None means no matching required).
            aad: The additional authenticated data.
            tolerance: The tolerance for the signature timestamp.
        """

        sig_raw, timestamp, sig_aad = pickle.loads(sig.extended_message)

        # Check if the timestamp is valid.
        # if not Timestamp.check_time_stamp(timestamp):
        #     QuantumSign.LOGGER.error("Stale signature timestamp.")
        #     return False

        # Check if the ID matches the target ID.
        if not bytes_eq(sig_aad, aad):
            QuantumSign.LOGGER.error(f"Invalid AAD.")
            return False

        # Verify the signature against the message.
        hashed_message = Hasher.hash(data=sig.extended_message, algorithm=QuantumSign.HASH_ALGORITHM)
        if not dilithium4.verify(pkey, hashed_message, sig.signature):
            QuantumSign.LOGGER.error("Invalid signature (message tampered).")
            return False

        # Check if the raw message matches the signature.
        if raw is not None and not bytes_eq(raw, sig_raw):
            QuantumSign.LOGGER.error("Invalid signature (raw message mismatch).")
            return False

        # If all checks pass, return True.
        return True


__all__ = ["QuantumSign"]
