from dataclasses import dataclass, field

from SNetwork.Utils.Types import Bytes


@dataclass(kw_only=True, frozen=True)
class AsymmetricKeyPair:
    public_key: Bytes = field(default=b"")
    secret_key: Bytes = field(default=b"")


@dataclass(kw_only=True, frozen=True)
class WrappedKeyPair:
    encapsulated: Bytes = field(default=b"")
    decapsulated: Bytes = field(default=b"")


__all__ = ["AsymmetricKeyPair", "WrappedKeyPair"]
