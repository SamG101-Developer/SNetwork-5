from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256

from src.Crypt.AsymmetricKeys import SecKey, PubKey
from src.Crypt.KeyPair import KeyPair, KEMKeyPair
from src.Utils.Types import Bytes


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
    def kem_wrap(their_ephemeral_public_key: PubKey, decapsulated_key: Bytes) -> KEMKeyPair:
        # Encapsulate the key and package both the encapsulated and decapsulated keys into a KEMKeyPair object.
        encapsulated_key = their_ephemeral_public_key.encrypt(
            plaintext=decapsulated_key,
            padding=OAEP(
                mgf=MGF1(SHA256()),
                algorithm=SHA256(),
                label=None
            ))
        return KEMKeyPair(encapsulated_key, decapsulated_key)

    @staticmethod
    def kem_unwrap(my_ephemeral_secret_key: SecKey, encapsulated_key: Bytes) -> KEMKeyPair:
        # Decapsulate the key and package both the encapsulated and decapsulated keys into a KEMKeyPair object.
        decapsulated_key = my_ephemeral_secret_key.decrypt(
            ciphertext=encapsulated_key,
            padding=OAEP(
                mgf=MGF1(SHA256()),
                algorithm=SHA256(),
                label=None
            ))
        return KEMKeyPair(encapsulated_key, decapsulated_key)
