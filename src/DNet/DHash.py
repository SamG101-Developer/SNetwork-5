from src.DNet.DNetwork import DNetworkConfig
from src.Utils.Types import Bytes, Int

from hashlib import md5
from ipaddress import IPv6Address


class DHash:
    @staticmethod
    def hash(value: Bytes, N: Int = DNetworkConfig.N) -> Int:
        return int(md5(value).hexdigest(), 16) % N

    @staticmethod
    def hash_address(address: IPv6Address) -> Int:
        return DHash.hash(address.packed, DNetworkConfig.N)
