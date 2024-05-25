from ipaddress import IPv6Address

# Ports for each layer of the network stack.
LAYER_1_PORT = 40_001
LAYER_2_PORT = 40_002
LAYER_3_PORT = 40_003
LAYER_4_PORT = 40_004

# Default IPv6 addresses.
DIRECTORY_IP = IPv6Address("fe80::7c7b:e49b:8cd:dc22")
DEFAULT_IPV6 = "::"

# Default values for the DHT.
DHT_KEY_LENGTH = 32
DHT_K_VALUE = 20
DHT_ALPHA = 3
DHT_STORE_PATH = "store/%s.dat"
