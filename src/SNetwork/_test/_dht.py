from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from threading import Lock

from SNetwork.Config import DHT_KEY_LENGTH
from SNetwork.Utils.Types import Bytes, Dict, Float, Int, List, Optional, Tuple, Json


def node_distance(a: Bytes, b: Bytes) -> Int:
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


@dataclass(kw_only=True)
class Connection:
    address: IPv6Address
    identifier: Bytes


@dataclass(kw_only=True)
class NodeLookupRequest:
    target_node_identifier: Bytes
    current_closest: Optional[Connection]
    lock: Lock = field(init=False, default_factory=Lock)
    queried_nodes: List[Connection] = field(init=False, default_factory=list)

    @property
    def closest_distance(self) -> Int:
        return node_distance(self.target_node_identifier, self.current_closest.identifier)


type KBucket = List[Connection]
type KBuckets = List[KBucket]


class DHTProtocol(Enum):
    Ping = 0
    Pong = 1
    PutResource = 2
    GetResource = 3
    ReturnResource = 4
    FindNode = 5
    FindNodeResponse = 6


class DHT:
    _this_id: Bytes
    _k_buckets: KBuckets
    _ping_queue: List[Tuple[Float, Connection]]
    _stored_keys: List[Bytes]
    _node_lookup_requests: Dict[Bytes, NodeLookupRequest]
    
    def __init__(self, identifier: Bytes) -> None:
        self._this_id = identifier
        self._k_buckets = [[] for _ in range(8 * DHT_KEY_LENGTH)]
        self._ping_queue = []
        self._stored_keys = []
        self._node_lookup_requests = {}
        
    def _handle_command(self, address: IPv6Address, request: Json) -> None:
        # Match the command to the appropriate handler.
        match request["command"]:
            case DHTProtocol.Ping.value:
                self._handle_ping(address, request)
            case DHTProtocol.Pong.value:
                self._handle_pong(address, request)
            case DHTProtocol.PutResource.value:
                self._handle_put_resource(address, request)
            case DHTProtocol.GetResource.value:
                self._handle_get_resource(address, request)
            case DHTProtocol.ReturnResource.value:
                self._handle_return_resource(address, request)
            case DHTProtocol.FindNode.value:
                self._handle_find_node(address, request)
            case DHTProtocol.FindNodeResponse.value:
                self._handle_find_node_response(address, request)

    def _handle_ping(self, address: IPv6Address, request: Json) -> None:
        pass

    def _handle_pong(self, address: IPv6Address, request: Json) -> None:
        pass

    def _handle_put_resource(self, address: IPv6Address, request: Json) -> None:
        pass

    def _handle_get_resource(self, address: IPv6Address, request: Json) -> None:
        pass

    def _handle_return_resource(self, address: IPv6Address, request: Json) -> None:
        pass

    def _handle_find_node(self, address: IPv6Address, request: Json) -> None:
        pass

    def _handle_find_node_response(self, address: IPv6Address, request: Json) -> None:
        pass
