from dataclasses import dataclass
from filelock import FileLock
import pickle

import keyring
from keyrings.alt.file import PlaintextKeyring

from SNetwork.QuantumCrypto.Certificate import X509Certificate
from SNetwork.Utils.Types import Bytes, Bool, Optional, Int
from SNetwork.Config import KEY_STORE_NAME


keyring.set_keyring(PlaintextKeyring())
lock = FileLock(f"{PlaintextKeyring().file_path}.lock")


@dataclass(kw_only=True, frozen=True)
class KeyStoreData:
    identifier: Bytes
    secret_key: Bytes
    public_key: Bytes
    certificate: Optional[X509Certificate]
    hashed_username: Bytes
    hashed_password: Bytes
    port: Int


class KeyManager:

    @staticmethod
    def get_info(hashed_username: Bytes) -> Optional[KeyStoreData]:
        # Get info from the keystore and convert from bytes into the dict.
        with lock:
            encoded_info = keyring.get_password(KEY_STORE_NAME, hashed_username.hex())
        info = pickle.loads(bytes.fromhex(encoded_info)) if encoded_info else None
        return info

    @staticmethod
    def set_info(info: KeyStoreData) -> None:
        # Encode the information into bytes and set it in the keystore.
        encoded_info = pickle.dumps(info)
        with lock:
            keyring.set_password(KEY_STORE_NAME, info.hashed_username.hex(), encoded_info.hex())

    @staticmethod
    def has_info(hashed_username: Bytes) -> Bool:
        with lock:
            return keyring.get_password(KEY_STORE_NAME, hashed_username.hex()) is not None

    @staticmethod
    def del_info(hashed_username: Bytes) -> None:
        with lock:
            keyring.delete_password(KEY_STORE_NAME, hashed_username.hex())


__all__ = ["KeyManager"]
