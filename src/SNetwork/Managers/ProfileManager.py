import logging, json

from SNetwork.Config import PROFILE_FILE, DIRECTORY_SERVICE_PUBLIC_FILE, DIRECTORY_SERVICE_PRIVATE_FILE, TESTING_PORT_ADJUST
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Types import Str, List
from SNetwork.Utils.Types import Bytes, Int, Optional, Tuple


class ProfileManager:
    @staticmethod
    def create_profile(username: Str, password: Str) -> None:
        # Hash the username and password.
        hashed_username = Hasher.hash(username.encode(), HashAlgorithm.SHA3_256)
        hashed_password = Hasher.hash(password.encode(), HashAlgorithm.SHA3_256)

        # Load the current profiles.
        with SafeFileOpen(PROFILE_FILE, "rb") as file:
            current_profiles = json.load(file)

        # Check if the username already exists
        if username in current_profiles:
            logging.error("Profile already exists")
            return

        # Get the next available port from the current profiles, and update the JSON file.
        else:
            ports = [int(current_profile["port"]) for current_profile in current_profiles.values()] or [40000]
            port = min(set(range(min(ports), max(ports) + 2)) - set(ports))
            current_profiles[username] = {"username": username, "password": hashed_password.hex(), "port": port}
            with SafeFileOpen(PROFILE_FILE, "w") as file:
                json.dump(current_profiles, file)

    @staticmethod
    def validate_profile(username: Str, password: Str) -> Optional[Tuple[Bytes, Bytes, Int]]:
        # Hash the username and password.
        hashed_username = Hasher.hash(username.encode(), HashAlgorithm.SHA3_256)
        hashed_password = Hasher.hash(password.encode(), HashAlgorithm.SHA3_256)

        # Load the current profiles.
        with SafeFileOpen(PROFILE_FILE, "rb") as file:
            current_profiles = json.load(file)

        # Check if the username exists.
        if username not in current_profiles:
            logging.error("Username doesn't exist")
            return None

        # Check if the password is correct. Todo: bytes_eq
        if hashed_password.hex() != current_profiles[username]["password"]:
            logging.error("Incorrect password")
            return None

        # Return the hashed username and port.
        return hashed_username, hashed_password, current_profiles[username]["port"] + TESTING_PORT_ADJUST

    @staticmethod
    def validate_directory_profile(username: Str) -> Optional[Tuple[Bytes, Bytes, Int, Bytes, AsymmetricKeyPair]]:
        # Hash the username and password.
        hashed_username = Hasher.hash(username.encode(), HashAlgorithm.SHA3_256)
        hashed_password = Hasher.hash(b"", HashAlgorithm.SHA3_256)

        # Load the current profiles.
        with SafeFileOpen(DIRECTORY_SERVICE_PUBLIC_FILE, "rb") as file:
            current_profiles = json.load(file)

        # Load the keys
        with SafeFileOpen(DIRECTORY_SERVICE_PRIVATE_FILE % username, "rb") as file:
            private_information = json.load(file)
            identifier = bytes.fromhex(private_information["identifier"])
            static_key_pair = AsymmetricKeyPair(
                public_key=bytes.fromhex(private_information["public_key"]),
                secret_key=bytes.fromhex(private_information["secret_key"]))

        # Return the hashed username and port.
        return hashed_username, hashed_password, current_profiles[username]["port"] + TESTING_PORT_ADJUST, identifier, static_key_pair

    @staticmethod
    def list_profiles() -> List[Str]:
        # Load the current profiles and print them.
        with SafeFileOpen(PROFILE_FILE, "rb") as file:
            current_profiles = json.load(file)
        return [username for username in current_profiles]
