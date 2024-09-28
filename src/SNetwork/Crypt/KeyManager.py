import keyring
from typing import TypedDict

from SNetwork.Crypt.AsymmetricKeys import PubKey, SecKey
from SNetwork.Crypt.Certificate import X509Certificate
from SNetwork.Utils.Json import SafeJson
from SNetwork.Utils.Types import Bytes, Bool
from SNetwork.Config import KEY_STORE_NAME


class KeyStoreData(TypedDict):
    identifier: Bytes
    secret_key: SecKey
    public_key: PubKey
    certificate: X509Certificate


class KeyManager:
    @staticmethod
    def get_info() -> KeyStoreData:
        info = SafeJson.loads(keyring.get_password(KEY_STORE_NAME, "default"))
        info = {
            "identifier": bytes.fromhex(info["identifier"]),
            "secret_key": SecKey.from_pem(info["secret_key"].encode()),
            "public_key": PubKey.from_pem(info["public_key"].encode()),
            "certificate": X509Certificate.from_pem(info["certificate"].encode())}
        return info

    @staticmethod
    def set_info(*, identifier: Bytes, secret_key: SecKey, public_key: PubKey, certificate: X509Certificate) -> None:
        info = {
            "identifier": identifier.hex(),
            "secret_key": secret_key.pem.decode(),
            "public_key": public_key.pem.decode(),
            "certificate": certificate.pem.decode()}
        keyring.set_password(KEY_STORE_NAME, "default", SafeJson.dumps(info).decode())

    @staticmethod
    def has_info() -> Bool:
        return keyring.get_password(KEY_STORE_NAME, "default") is not None

    @staticmethod
    def del_info() -> None:
        keyring.delete_password(KEY_STORE_NAME, "default")


__all__ = ["KeyManager"]
