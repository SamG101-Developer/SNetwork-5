from SNetwork.Crypt.AsymmetricKeys import PubKey, SecKey
from SNetwork.Utils.Types import Bytes

from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


class KeyManager:
    @staticmethod
    def get_identifier() -> Bytes:
        id_ = open("_crypt/identifier.txt", "r").read()
        return bytes.fromhex(id_)

    @staticmethod
    def get_static_public_key() -> PubKey:
        pem = open("_crypt/public_key.pem", "rb").read()
        return PubKey(load_pem_public_key(pem))

    @staticmethod
    def get_static_secret_key() -> SecKey:
        pem = open("_crypt/secret_key.pem", "rb").read()
        return SecKey(load_pem_private_key(pem, None))


__all__ = ["KeyManager"]
