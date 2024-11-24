from enum import Enum
import hashlib

from SNetwork.Utils.Types import Bytes


class HashAlgorithm:
    SHA3_224 = hashlib.sha3_224
    SHA3_256 = hashlib.sha3_256
    SHA3_384 = hashlib.sha3_384
    SHA3_512 = hashlib.sha3_512

    SHA2_224 = hashlib.sha224
    SHA2_256 = hashlib.sha256
    SHA2_384 = hashlib.sha384
    SHA2_512 = hashlib.sha512


class Hasher:
    @staticmethod
    def hash[T](data: Bytes, algorithm: T) -> Bytes:
        return algorithm(data).digest()


__all__ = ["Hasher", "HashAlgorithm"]
