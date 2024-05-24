from cryptography.hazmat.primitives.hashes import Hash as _Hash, HashAlgorithm as _HashAlgorithm, SHA3_224, SHA3_256
from src.Utils.Types import Bytes


class Hasher:
    @staticmethod
    def hash(value: Bytes, algorithm: _HashAlgorithm) -> Bytes:
        hasher = _Hash(algorithm)
        hasher.update(value)
        return hasher.finalize()
