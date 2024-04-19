from ipaddress import IPv4Address
import socket, platform


def my_address() -> IPv4Address:
    my_name = socket.gethostname() + (".local" if platform.machine() == "armv7l" else "")
    my_ip = socket.gethostbyname(my_name)
    return IPv4Address(my_ip)
