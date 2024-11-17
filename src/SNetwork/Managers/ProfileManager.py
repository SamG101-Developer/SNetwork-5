import logging
import json

from SNetwork.Config import PROFILE_FILE
from SNetwork.Utils.Types import Str
from SNetwork.Crypt.Hash import Hasher, HashAlgorithms
from SNetwork.Utils.Types import Bytes, Int, Optional, Tuple


class ProfileManager:
    @staticmethod
    def create_profile(username: Str, password: Str) -> None:
        # Hash the username and password.
        hashed_username = Hasher.hash(username.encode(), HashAlgorithms.SHA3_256())
        hashed_password = Hasher.hash(password.encode(), HashAlgorithms.SHA3_256())

        # Load the current profiles and check if the username already exists.
        current_profiles = json.load(open(PROFILE_FILE, "rb"))
        if username in current_profiles:
            logging.error("Profile already exists")
            return

        # Get the next available port from the current profiles, and update the JSON file.
        else:
            ports = [int(current_profiles[profile]["port"]) for profile in current_profiles]
            port = min(set(range(min(ports), max(ports) + 2)) - set(ports))
            current_profiles[username] = {"username": username, "password": hashed_password.hex(), "port": port}
            json.dump(current_profiles, open(PROFILE_FILE, "w"))

    @staticmethod
    def validate_profile(username: Str, password: Str) -> Optional[Tuple[Bytes, Int]]:
        # Hash the username and password.
        hashed_username = Hasher.hash(username.encode(), HashAlgorithms.SHA3_256())
        hashed_password = Hasher.hash(password.encode(), HashAlgorithms.SHA3_256())

        # Load the current profiles and check if the username exists.
        current_profiles = json.load(open(PROFILE_FILE, "rb"))
        if username not in current_profiles:
            logging.error("Username doesn't exist")
            return None

        # Check if the password is correct. Todo: bytes_eq
        if hashed_password.hex() != current_profiles[username]["password"]:
            logging.error("Incorrect password")
            return None

        # Return the hashed username and port.
        return hashed_username, current_profiles[username]["port"]

    @staticmethod
    def list_profiles() -> None:
        # Load the current profiles and print them.
        current_profiles = json.load(open(PROFILE_FILE, "rb"))
        for username, profile in current_profiles.items():
            print(f"Profile: {username}")
