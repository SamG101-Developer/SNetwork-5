from __future__ import annotations
import struct, time

from SNetwork.Utils.Types import Bytes, Int
from SNetwork.Config import MESSAGE_SIGNATURE_TOLERANCE


class Timestamp:
    @staticmethod
    def generate_time_stamp() -> Bytes:
        return struct.pack("!d", time.time())

    @staticmethod
    def check_time_stamp(time_stamp: Bytes, tolerance: Int = MESSAGE_SIGNATURE_TOLERANCE) -> bool:
        return time.time() - struct.unpack("!d", time_stamp)[0] < tolerance
