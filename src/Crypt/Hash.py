from cryptography.hazmat.primitives.hashes import Hash, HashAlgorithm, SHA3_224, SHA3_256
from src.Utils.Types import Bytes, Int, Type


class Hasher:
    @staticmethod
    def hash(value: Bytes, algorithm: HashAlgorithm) -> Bytes:
        hasher = Hash(algorithm)
        hasher.update(value)
        return hasher.finalize()
