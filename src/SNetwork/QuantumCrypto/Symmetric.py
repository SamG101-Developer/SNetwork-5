import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from SNetwork.Utils.Types import Bytes


class SymmetricEncryption:
    """
    Symmetric encryption is used to secure connections, providing confidentiality and integrity. It is used to encrypt
    and decrypt data, and to wrap and unwrap new keys.
    """

    ALGORITHM    = AESOCB3
    KEY_LENGTH   = 32
    NONCE_LENGTH = 12

    @staticmethod
    def generate_key() -> Bytes:
        # Generate a random key and return it.
        random_key = secrets.token_bytes(SymmetricEncryption.KEY_LENGTH)
        return random_key

    @staticmethod
    def wrap_new_key(*, current_key: Bytes, new_key: Bytes) -> Bytes:
        # Wrap the new key using the current key and return it.
        wrapped_key = aes_key_wrap(current_key, new_key)
        return wrapped_key

    @staticmethod
    def unwrap_new_key(*, current_key: Bytes, wrapped_key: Bytes) -> Bytes:
        # Unwrap the new key using the current key and return it.
        unwrapped_key = aes_key_unwrap(current_key, wrapped_key)
        return unwrapped_key

    @staticmethod
    def encrypt(*, data: Bytes, key: Bytes) -> Bytes:
        # Generate a random nonce, encrypt the plaintext and return it with the nonce prepended.
        nonce = os.urandom(SymmetricEncryption.NONCE_LENGTH)
        encryption_engine = SymmetricEncryption.ALGORITHM(key)
        ciphertext = encryption_engine.encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt(*, data: Bytes, key: Bytes) -> Bytes:
        # Split the nonce anc ciphertext, decrypt the data and return it.
        nonce, ciphertext = data[:SymmetricEncryption.NONCE_LENGTH], data[SymmetricEncryption.NONCE_LENGTH:]
        decryption_engine = SymmetricEncryption.ALGORITHM(key)
        plaintext = decryption_engine.decrypt(nonce, ciphertext, None)
        return plaintext


__all__ = ["SymmetricEncryption"]
