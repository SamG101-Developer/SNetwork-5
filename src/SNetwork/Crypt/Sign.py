from __future__ import annotations

import logging
import struct
import time

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.exceptions import InvalidSignature

from SNetwork.Crypt.AsymmetricKeys import SecKey, PubKey, KeyPair
from SNetwork.Crypt.Hash import Hasher, HashAlgorithms
from SNetwork.Utils.Types import Bytes, Bool


class Signer:
    """
    Digital signing is used to sign messages, so that the recipient can verify that the message was sent by the sender.
    There are methods for signing, verifying and generating key pairs. The authentication isn't just private-key-signing
    oriented; it also uses timestamps, and the recipient's ID to prevent replay attacks.
    """

    PADDING_SCHEME = PSS(MGF1(HashAlgorithms.SHA3_224()), PSS.MAX_LENGTH)

    @staticmethod
    def generate_key_pair() -> KeyPair:
        # Generate a key pair and package it into a KeyPair object.
        secret_key = SecKey(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        public_key = secret_key.pub_key()
        return KeyPair(secret_key, public_key)

    @staticmethod
    def sign(my_static_private_key: SecKey, message: Bytes, their_id: Bytes) -> Bytes:
        # Add the id to the message.
        message += their_id
        message += struct.pack("!d", time.time())

        # Sign the hashed message.
        signature = my_static_private_key.sign(
            data=message,
            padding=PSS(MGF1(HashAlgorithms.SHA3_224()), PSS.MAX_LENGTH),
            algorithm=HashAlgorithms.SHA3_224())
        return signature

    @staticmethod
    def verify(their_static_public_key: PubKey, message: Bytes, signature: Bytes, target_id: Bytes, check_time: Bool = True) -> Bool:
        # Extract the message and reproduce the hash.
        timestamp = struct.unpack("!d", message[-8:])[0]
        candidate_id = message[-HashAlgorithms.SHA3_256.digest_size - 8:-8]

        try:
            # Check the timestamp and intended receiver.
            assert not check_time or check_time and timestamp - time.time() < 5, f"Signature is stale by {timestamp - time.time() - 5}s"
            assert candidate_id == target_id, f"Received Candidate ID '{candidate_id[:20]}...' != Target ID '{target_id[:20]}...'"

            # Verify the signature against the message.
            their_static_public_key.verify(
                data=message,
                signature=signature,
                padding=PSS(MGF1(HashAlgorithms.SHA3_224()), PSS.MAX_LENGTH),
                algorithm=HashAlgorithms.SHA3_224())
            return True

        # Handle an invalid signature.
        except InvalidSignature:
            logging.error("Invalid signature.")
            return False

        # Handle an assertion error (conditions for the timestamp and recipient ID)
        except AssertionError as e:
            logging.error(e)
            return False

        # Any other error
        except Exception as e:
            logging.error(e)
            raise e


__all__ = ["Signer"]
