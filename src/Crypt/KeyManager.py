from src.Crypt.AsymmetricKeys import PubKey, SecKey
from src.Utils.Types import Bytes

from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


class KeyManager:
    @staticmethod
    def get_identifier() -> Bytes:
        id = open("_crypt/identifier.txt", "r").read()
        return bytes.fromhex(id)

    @staticmethod
    def get_static_public_key() -> PubKey:
        pem = open("_crypt/public_key.pem", "rb").read()
        return PubKey(load_pem_public_key(pem))

    @staticmethod
    def get_static_secret_key() -> SecKey:
        pem = open("_crypt/secret_key.pem", "rb").read()
        return SecKey(load_pem_private_key(pem, None))
