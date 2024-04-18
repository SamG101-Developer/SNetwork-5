from enum import Enum


class DNetworkConfig:
    M = 16
    N = pow(2, M)


# class DNetworkProtocol(Enum):
#     DNET_LOOKUP = 0
#     DNET_LOOKUP_NODE = 1
#     DNET_LOOKUP_RESPONSE = 2
#     DNET_GET_NEIGHBORS = 3
#     DNET_UPDATE_SUCCESSOR = 4
#     DNET_UPDATE_PREDECESSOR = 5
#     DNET_MIGRATE_DATA = 6
#     DNET_ACC_INBOUND_FILE = 7
#     DNET_ACC_INBOUND_BACKUP_FILE = 8
#     DNET_CLEAR_BACKUP = 9
#     DNET_REQUEST_FILE = 10
#     DNET_PING = 11
