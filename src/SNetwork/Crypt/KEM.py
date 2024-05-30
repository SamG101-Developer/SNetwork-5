from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1

from SNetwork.Crypt.AsymmetricKeys import SecKey, PubKey, KeyPair, KEMKeyPair
from SNetwork.Crypt.Hash import HashAlgorithms
from SNetwork.Utils.Types import Bytes


class KEM:
    """
    Key encapsulation is used to encapsulate a key, so that it can be sent to the recipient. There are methods for
    encapsulating, decapsulating and generating key pairs.
    """

    @staticmethod
    def generate_key_pair() -> KeyPair:
        # Generate a key pair and package it into a KeyPair object.
        secret_key = SecKey(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        public_key = secret_key.pub_key()
        return KeyPair(secret_key, public_key)

    @staticmethod
    def kem_wrap(*, their_ephemeral_public_key: PubKey, decapsulated_key: Bytes) -> KEMKeyPair:
        # Encapsulate the key.
        encapsulated_key = their_ephemeral_public_key.encrypt(
            plaintext=decapsulated_key,
            padding=OAEP(
                mgf=MGF1(HashAlgorithms.SHA2_256()),
                algorithm=HashAlgorithms.SHA2_256(),
                label=None))

        # Package both the encapsulated and decapsulated keys into a KEMKeyPair object.
        return KEMKeyPair(encapsulated_key, decapsulated_key)

    @staticmethod
    def kem_unwrap(*, my_ephemeral_secret_key: SecKey, encapsulated_key: Bytes) -> KEMKeyPair:
        # Decapsulate the key.
        decapsulated_key = my_ephemeral_secret_key.decrypt(
            ciphertext=encapsulated_key,
            padding=OAEP(
                mgf=MGF1(HashAlgorithms.SHA2_256()),
                algorithm=HashAlgorithms.SHA2_256(),
                label=None))

        # Package both the encapsulated and decapsulated keys into a KEMKeyPair object.
        return KEMKeyPair(encapsulated_key, decapsulated_key)


__all__ = ["KEM"]
