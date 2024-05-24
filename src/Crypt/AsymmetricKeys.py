from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.hashes import HashAlgorithm

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PublicFormat, PrivateFormat
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_der_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

from src.Utils.Types import Bytes, Str


class PubKey:
    _public_key: RSAPublicKey

    def __init__(self, public_key: RSAPublicKey) -> None:
        self._public_key = public_key

    @property
    def der(self) -> Bytes:
        return self._public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)

    @property
    def pem(self) -> Bytes:
        return self._public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

    @staticmethod
    def from_der(der: Bytes) -> PubKey:
        return PubKey(load_der_public_key(der))

    @staticmethod
    def from_pem(pem: Bytes) -> PubKey:
        return PubKey(load_pem_public_key(pem))

    def verify(self, data: Bytes, signature: Bytes, padding: AsymmetricPadding, algorithm: HashAlgorithm) -> None:
        self._public_key.verify(signature, data, padding, algorithm)

    def encrypt(self, plaintext: Bytes, padding: AsymmetricPadding) -> Bytes:
        return self._public_key.encrypt(plaintext, padding)


class SecKey:
    _secret_key: RSAPrivateKey

    def __init__(self, secret_key: RSAPrivateKey) -> None:
        self._secret_key = secret_key

    @property
    def der(self) -> Bytes:
        return self._secret_key.private_bytes(encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())

    @property
    def pem(self) -> Str:
        return self._secret_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()).decode()

    @staticmethod
    def from_der(der: Bytes) -> SecKey:
        return SecKey(load_der_private_key(der, None))

    @staticmethod
    def from_pem(pem: Bytes) -> SecKey:
        return SecKey(load_pem_private_key(pem, None))

    def pub_key(self) -> PubKey:
        return PubKey(self._secret_key.public_key())

    def sign(self, data: Bytes, padding: AsymmetricPadding, algorithm: HashAlgorithm) -> Bytes:
        return self._secret_key.sign(data, padding, algorithm)

    def decrypt(self, ciphertext: Bytes, padding: AsymmetricPadding) -> Bytes:
        return self._secret_key.decrypt(ciphertext, padding)
