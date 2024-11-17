from pqcrypto.kem import kyber1024

from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair, WrappedKeyPair
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Types import Bytes


class QuantumKem:
    LOGGER = isolated_logger(LoggerHandlers.CRYPTOGRAPHY)

    @staticmethod
    def generate_key_pair() -> AsymmetricKeyPair:
        # Generate a public and secret key pair.
        public_key, secret_key = kyber1024.generate_keypair()
        return AsymmetricKeyPair(public_key=public_key, secret_key=secret_key)

    @staticmethod
    def encapsulate(*, public_key: Bytes) -> WrappedKeyPair:
        # Generate a shared key and encapsulation.
        decapsulated, encapsulated = kyber1024.encrypt(public_key)
        return WrappedKeyPair(decapsulated=decapsulated, encapsulated=encapsulated)

    @staticmethod
    def decapsulate(*, secret_key: Bytes, encapsulated: Bytes) -> WrappedKeyPair:
        # Decapsulate the shared key.
        decapsulated = kyber1024.decrypt(secret_key, encapsulated)
        return WrappedKeyPair(decapsulated=decapsulated, encapsulated=encapsulated)


__all__ = ["QuantumKem"]
