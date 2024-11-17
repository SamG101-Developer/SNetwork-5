import keyring
from keyrings.alt.file import PlaintextKeyring
from dataclasses import dataclass

from SNetwork.Crypt.AsymmetricKeys import PubKey, SecKey
from SNetwork.QuantumCrypto.Certificate import X509Certificate
from SNetwork.Utils.Json import SafeJson
from SNetwork.Utils.Types import Bytes, Bool, Optional
from SNetwork.Config import KEY_STORE_NAME


keyring.set_keyring(PlaintextKeyring())


@dataclass(kw_only=True, frozen=True)
class KeyStoreData:
    identifier: Bytes
    secret_key: SecKey
    public_key: PubKey
    certificate: X509Certificate
    hashed_username: Bytes
    hashed_password: Bytes


class KeyManager:
    @staticmethod
    def get_info(hashed_username: Bytes) -> Optional[KeyStoreData]:
        info = SafeJson.loads(keyring.get_password(KEY_STORE_NAME, hashed_username.hex()))
        if not info:
            return None

        return KeyStoreData(
            identifier=bytes.fromhex(info["identifier"]),
            secret_key=SecKey.from_pem(info["secret_key"].encode()),
            public_key=PubKey.from_pem(info["public_key"].encode()),
            certificate=X509Certificate.from_pem(info["certificate"].encode()),
            hashed_username=bytes.fromhex(info["hashed_username"]),
            hashed_password=bytes.fromhex(info["hashed_password"]))

    @staticmethod
    def set_info(
            *, identifier: Bytes, secret_key: SecKey, public_key: PubKey, certificate: X509Certificate,
            hashed_profile_username: Bytes, hashed_profile_password: Bytes) -> None:

        info = {
            "identifier": identifier.hex(),
            "secret_key": secret_key.pem.decode(),
            "public_key": public_key.pem.decode(),
            "certificate": certificate.pem.decode(),
            "hashed_profile_username": hashed_profile_username.hex(),
            "hashed_profile_password": hashed_profile_password.hex()}
        keyring.set_password(KEY_STORE_NAME, hashed_profile_username.hex(), SafeJson.dumps(info).decode())

    @staticmethod
    def has_info(hashed_profile_username: Bytes) -> Bool:
        return keyring.get_password(KEY_STORE_NAME, hashed_profile_username.hex()) is not None

    @staticmethod
    def del_info(hashed_profile_username: Bytes) -> None:
        keyring.delete_password(KEY_STORE_NAME, hashed_profile_username.hex())


__all__ = ["KeyManager"]
