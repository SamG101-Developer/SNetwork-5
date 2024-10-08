from ipaddress import IPv6Address

# Ports for each layer of the network stack.
LAYER_1_PORT = 40_001
LAYER_2_PORT = 40_002
LAYER_3_PORT = 40_003
LAYER_4_PORT = 40_004
LAYER_D_PORT = 40_005

# Connection related constants.
CONNECTION_TIMEOUT = 5
HOP_COUNT = 3

# Default IPv6 addresses.
DIRECTORY_IP = IPv6Address("fe80::7c7b:e49b:8cd:dc22")
DIRECTORY_IDENTIFIER = b"directory"  # Todo: link to cert / keys when created
DEFAULT_IPV6 = "::"
LOOPBACK_IPV6 = "::1"
LOCAL_HOST = "localhost"
MAX_TCP_LISTEN = 20
HTTP_CONNECT_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"

# Storage related constants.
KEY_STORE_NAME = "snetwork.static_keys"

# Default values for the DHT.
DHT_KEY_LENGTH = 32
DHT_K_VALUE = 20
DHT_ALPHA = 3
DHT_STORE_PATH = "store/%s.dat"
