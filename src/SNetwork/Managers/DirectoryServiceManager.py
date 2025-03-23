import json
import os
import pathlib
import random
import socket
from ipaddress import IPv6Address

from SNetwork.Config import DIRECTORY_SERVICE_PUBLIC_FILE, DIRECTORY_SERVICE_PRIVATE_FILE, TESTING_PORT_ADJUST
from SNetwork.Managers.ProfileManager import ProfileManager
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Types import Bytes, Int, Bool, Str, Optional, Tuple, Dict, List


class DirectoryServiceManager:
    @staticmethod
    def create_directory_profile(username: str) -> Bool:
        # Generate a static key pair and get the address of the current machine.
        static_key_pair = QuantumSign.generate_key_pair()
        this_address = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET6)[0][4][0]

        # Check the current directory services for the name.
        with SafeFileOpen(DIRECTORY_SERVICE_PUBLIC_FILE, "rb") as file:
            directory_services = json.load(file)
        if username in directory_services: return False

        # Get the next available port from the current directory services.
        ports = [int(directory_service["port"]) for directory_service in directory_services.values()] or [50000]
        port = min(set(range(min(ports), max(ports) + 2)) - set(ports))

        # Generate the public information for the directory service.
        public_directory_service_entry = {
            "name": username,
            "identifier": Hasher.hash(static_key_pair.public_key, HashAlgorithm.SHA3_256).hex(),
            "public_key": static_key_pair.public_key.hex(),
            "address": this_address,
            "port": port}

        # Generate the private information for the directory service.
        private_directory_service_entry = public_directory_service_entry | {
            "secret_key": static_key_pair.secret_key.hex()}

        # Update the directory services file.
        directory_services[username] = public_directory_service_entry
        with SafeFileOpen(DIRECTORY_SERVICE_PUBLIC_FILE, "w") as file:
            json.dump(directory_services, file)
        with SafeFileOpen(DIRECTORY_SERVICE_PRIVATE_FILE % username, "w") as file:
            json.dump(private_directory_service_entry, file, indent=4)

        # Make DIRECTORY_SERVICE_PRIVATE_FILE % name readonly with 0o400 permissions.
        path = pathlib.Path(DIRECTORY_SERVICE_PRIVATE_FILE % username)
        path.chmod(0o400)

        # Key and certificate information, ands et information into the keyring.
        identifier = Hasher.hash(static_key_pair.public_key, HashAlgorithm.SHA3_256)
        hashed_username, hashed_password, *_ = DirectoryServiceManager.validate_directory_profile(username)
        ProfileManager._generate_profile_certificate(hashed_username, hashed_password, identifier, static_key_pair)
        return True

    @staticmethod
    def get_random_directory_profile(exclude: List[Str] = None) -> tuple[Str, IPv6Address, Int, Bytes, Bytes]:
        # Load the current directory services.
        with SafeFileOpen(DIRECTORY_SERVICE_PUBLIC_FILE, "rb") as file:
            directory_services = json.load(file)

        # Choose a random directory service to connect to.
        name = random.choice([k for k in directory_services.keys() if k not in (exclude or [])])
        entry = directory_services[name]
        return name, IPv6Address(entry["address"]), entry["port"] + TESTING_PORT_ADJUST, bytes.fromhex(entry["identifier"]), bytes.fromhex(entry["public_key"])

    @staticmethod
    def validate_directory_profile(username: Str) -> Optional[Tuple[Bytes, Bytes, Int, Bytes, AsymmetricKeyPair]]:
        # Hash the username and password.
        hashed_username = Hasher.hash(username.encode(), HashAlgorithm.SHA3_256)
        hashed_password = Hasher.hash(b"", HashAlgorithm.SHA3_256)
        current_profiles = DirectoryServiceManager._load_directory_profiles()

        # Check if the username exists.
        if not os.path.exists(DIRECTORY_SERVICE_PRIVATE_FILE % username):
            return None

        # Load the keys
        with SafeFileOpen(DIRECTORY_SERVICE_PRIVATE_FILE % username, "rb") as file:
            private_information = json.load(file)
            identifier = bytes.fromhex(private_information["identifier"])
            static_key_pair = AsymmetricKeyPair(
                public_key=bytes.fromhex(private_information["public_key"]),
                secret_key=bytes.fromhex(private_information["secret_key"]))

        # Return the hashed username and port.
        return (
            hashed_username, hashed_password, current_profiles[username]["port"] + TESTING_PORT_ADJUST, identifier,
            static_key_pair)

    @staticmethod
    def _load_directory_profiles() -> Dict:
        # Load the directory profiles.
        with SafeFileOpen(DIRECTORY_SERVICE_PUBLIC_FILE, "rb") as file:
            directory_profiles = json.load(file)
        return directory_profiles
