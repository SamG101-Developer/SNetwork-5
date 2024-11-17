from dataclasses import dataclass
from SNetwork.Utils.Types import Bytes


@dataclass(kw_only=True, frozen=True)
class AsymmetricKeyPair:
    public_key: Bytes
    secret_key: Bytes


@dataclass(kw_only=True, frozen=True)
class WrappedKeyPair:
    encapsulated: Bytes
    decapsulated: Bytes


__all__ = ["AsymmetricKeyPair", "WrappedKeyPair"]
