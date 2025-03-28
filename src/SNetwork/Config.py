# Connection related constants.
import os

CONNECTION_TIMEOUT = 5
HOP_COUNT = 3
CONNECTION_TOKEN_LENGTH = 32

# Default IPv6 addresses.
DEFAULT_IPV6 = "::"
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
PROFILE_CACHE = "profiles/profile-cache/%s.json"
DIRECTORY_SERVICE_PUBLIC_FILE = "profiles/directory-service.json"
DIRECTORY_SERVICE_PRIVATE_FILE = os.path.join("profiles", "directory-service-servers", "%s.json")
DIRECTORY_SERVICE_NODE_CACHE = "profiles/directory-service-node-cache/%s.json"

# Cryptographic constants.
IDENTIFIER_LENGTH = 32
TOLERANCE_MESSAGE_SIGNATURE = 60
TOLERANCE_CERTIFICATE_SIGNATURE = 60 * 60 * 24 * 365

TESTING_PORT_ADJUST = 400
