from ipaddress import IPv6Address
import json, pathlib, random, socket

from SNetwork.Config import DIRECTORY_SERVICE_PUBLIC_FILE, DIRECTORY_SERVICE_PRIVATE_FILE
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Types import Bytes, Int, Str, Bool


class DirectoryServiceManager:
    @staticmethod
    def new_directory_service(name: str) -> Bool:
        # Generate a static key pair and get the address of the current machine.
        static_key_pair = QuantumSign.generate_key_pair()
        this_address = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET6)[0][4][0]

        # Check the current directory services for the name.
        with SafeFileOpen(DIRECTORY_SERVICE_PUBLIC_FILE, "rb") as file:
            directory_services = json.load(file)
        if name in directory_services: return False

        # Get the next available port from the current directory services.
        ports = [int(directory_service["port"]) for directory_service in directory_services.values()] or [50000]
        port = min(set(range(min(ports), max(ports) + 2)) - set(ports))

        # Generate the public information for the directory service.
        public_directory_service_entry = {
            "name": name,
            "identifier": Hasher.hash(static_key_pair.public_key, HashAlgorithm.SHA3_256).hex(),
            "public_key": static_key_pair.public_key.hex(),
            "address": this_address,
            "port": port}

        # Generate the private information for the directory service.
        private_directory_service_entry = public_directory_service_entry | {
            "secret_key": static_key_pair.secret_key.hex()}

        # Update the directory services file.
        directory_services[name] = public_directory_service_entry
        with SafeFileOpen(DIRECTORY_SERVICE_PUBLIC_FILE, "w") as file:
            json.dump(directory_services, file)
        with SafeFileOpen(DIRECTORY_SERVICE_PRIVATE_FILE % name, "w") as file:
            json.dump(private_directory_service_entry, file)

        # Make DIRECTORY_SERVICE_PRIVATE_FILE % name readonly with 0o400 permissions.
        path = pathlib.Path(DIRECTORY_SERVICE_PRIVATE_FILE % name)
        path.chmod(0o400)

        return True

    @staticmethod
    def get_random_directory_service() -> tuple[IPv6Address, Int, Bytes]:
        # Load the current directory services.
        with SafeFileOpen(DIRECTORY_SERVICE_PUBLIC_FILE, "rb") as file:
            directory_services = json.load(file)

        # Choose a random directory service to connect to.
        name = random.choice(list(directory_services.keys()))
        entry = directory_services[name]
        return IPv6Address(entry["address"]), entry["port"], bytes.fromhex(entry["identifier"])
