from dataclasses import dataclass

from src.Crypt.AsymmetricKeys import PubKey, SecKey


@dataclass
class KeyPair:
    secret_key: SecKey
    public_key: PubKey


@dataclass
class KEMKeyPair:
    encapsulated: bytes
    decapsulated: bytes
