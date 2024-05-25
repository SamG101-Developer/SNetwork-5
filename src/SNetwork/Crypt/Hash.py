from cryptography.hazmat.primitives.hashes import Hash, HashAlgorithm
from cryptography.hazmat.primitives.hashes import SHA3_224, SHA3_256, SHA3_384, SHA3_512
from cryptography.hazmat.primitives.hashes import SHA224 as SHA2_224, SHA256 as SHA2_256, SHA384 as SHA2_384, \
    SHA512 as SHA2_512

from SNetwork.Utils.Types import Bytes


class Hasher:
    @staticmethod
    def hash(value: Bytes, algorithm: HashAlgorithm) -> Bytes:
        hasher = Hash(algorithm)
        hasher.update(value)
        return hasher.finalize()


class HashAlgorithms:
    SHA3_224 = SHA3_224
    SHA3_256 = SHA3_256
    SHA3_384 = SHA3_384
    SHA3_512 = SHA3_512

    SHA2_224 = SHA2_224
    SHA2_256 = SHA2_256
    SHA2_384 = SHA2_384
    SHA2_512 = SHA2_512


__all__ = ["Hasher", "HashAlgorithms"]
