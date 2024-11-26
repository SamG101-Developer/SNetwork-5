import json

import keyring
from keyrings.alt.file import PlaintextKeyring
from dataclasses import dataclass

from SNetwork.QuantumCrypto.Certificate import X509Certificate
from SNetwork.Utils.Types import Bytes, Bool, Optional
from SNetwork.Config import KEY_STORE_NAME


keyring.set_keyring(PlaintextKeyring())


@dataclass(kw_only=True, frozen=True)
class KeyStoreData:
    identifier: Bytes
    secret_key: Bytes
    public_key: Bytes
    certificate: X509Certificate
    hashed_username: Bytes
    hashed_password: Bytes


class KeyManager:
    @staticmethod
    def get_info(hashed_username: Bytes) -> Optional[KeyStoreData]:
        info = json.loads(keyring.get_password(KEY_STORE_NAME, hashed_username.hex()))
        if not info:
            return None

        return KeyStoreData(
            identifier=bytes.fromhex(info["identifier"]),
            secret_key=bytes.fromhex(info["secret_key"]),
            public_key=bytes.fromhex(info["public_key"]),
            certificate=json.loads(bytes.fromhex(info["certificate"])),
            hashed_username=bytes.fromhex(info["hashed_username"]),
            hashed_password=bytes.fromhex(info["hashed_password"]))

    @staticmethod
    def set_info(
            *, identifier: Bytes, secret_key: Bytes, public_key: Bytes, certificate: X509Certificate,
            hashed_profile_username: Bytes, hashed_profile_password: Bytes) -> None:

        info = {
            "identifier": identifier.hex(),
            "secret_key": secret_key.hex(),
            "public_key": public_key.hex(),
            "certificate": json.dumps(certificate).encode().hex(),
            "hashed_username": hashed_profile_username.hex(),
            "hashed_password": hashed_profile_password.hex()}
        keyring.set_password(KEY_STORE_NAME, hashed_profile_username.hex(), json.dumps(info))

    @staticmethod
    def has_info(hashed_profile_username: Bytes) -> Bool:
        return keyring.get_password(KEY_STORE_NAME, hashed_profile_username.hex()) is not None

    @staticmethod
    def del_info(hashed_profile_username: Bytes) -> None:
        keyring.delete_password(KEY_STORE_NAME, hashed_profile_username.hex())


__all__ = ["KeyManager"]
