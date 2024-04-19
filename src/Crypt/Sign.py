from __future__ import annotations

import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.exceptions import InvalidSignature

from src.Crypt.AsymmetricKeys import SecKey, PubKey
from src.Crypt.Hash import Hasher, SHA3_224
from src.Crypt.KeyPair import KeyPair
from src.Utils.Types import Bytes, Bool


class Signer:
    """
    Digital signing is used to sign messages, so that the recipient can verify that the message was sent by the sender.
    There are methods for signing, verifying and generating key pairs. The authentication isn't just private-key-signing
    oriented; it also uses timestamps, and the recipient's ID to prevent replay attacks.
    """

    PADDING_SCHEME = PSS(MGF1(SHA3_224()), PSS.MAX_LENGTH)

    @staticmethod
    def generate_key_pair() -> KeyPair:
        # Generate a key pair and package it into a KeyPair object.
        secret_key = SecKey(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        public_key = secret_key.pub_key()
        return KeyPair(secret_key, public_key)

    @staticmethod
    def sign(my_static_private_key: SecKey, message: Bytes, their_id: Bytes) -> Bytes:
        # Ad the id to the message, hash it, and sign it.
        message += Hasher.hash(their_id, SHA3_224())
        signature = my_static_private_key.sign(
            data=message,
            padding=PSS(MGF1(SHA3_224()), PSS.MAX_LENGTH),
            algorithm=SHA3_224())
        return signature

    @staticmethod
    def verify(their_static_public_key: PubKey, message: Bytes, signature: Bytes, my_id: Bytes) -> Bool:
        # Extract the message and reproduce the hash.
        recipient_id = message[-SHA3_224.digest_size:]

        try:
            assert recipient_id == Hasher.hash(my_id, SHA3_224()), f"Recipient ID {str(recipient_id)[:20]}... != {str(my_id)[:20]}..."
            their_static_public_key.verify(
                data=message,
                signature=signature,
                padding=PSS(MGF1(SHA3_224()), PSS.MAX_LENGTH),
                algorithm=SHA3_224())
            return True

        except InvalidSignature:
            logging.error("Invalid signature.")
            return False

        except AssertionError as e:
            logging.error(e)
            return False
