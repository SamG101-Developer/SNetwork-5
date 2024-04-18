from src.DNet.DNodeAddress import DNodeAddress
from src.DNet.DNetwork import DNetworkConfig
from src.Utils.Types import Bytes, Int

from hashlib import md5


class DHash:
    @staticmethod
    def hash(value: Bytes, N: Int = DNetworkConfig.N) -> Int:
        return int(md5(value).hexdigest(), 16) % N

    @staticmethod
    def hash_address(address: DNodeAddress) -> Int:
        return DHash.hash(address.ip.packed + str(address.port).encode(), DNetworkConfig.N)
