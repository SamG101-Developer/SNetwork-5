from ipaddress import IPv6Address

# Connection related constants.
CONNECTION_TIMEOUT = 5
HOP_COUNT = 3
CONNECTION_TOKEN_LENGTH = 32

# Default IPv6 addresses.
DIRECTORY_ADDRESS = IPv6Address("fe80::7c7b:e49b:8cd:dc22")
DIRECTORY_PORT = 40_000
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

# PROFILES
PROFILE_FILE = "profiles/profiles.json"

# Cryptographic constants.
IDENTIFIER_LENGTH = 32
MESSAGE_SIGNATURE_TOLERANCE = 60
