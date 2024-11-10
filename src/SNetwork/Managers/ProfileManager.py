import logging
import json

from SNetwork.Utils.Types import Bytes, Str
from SNetwork.Crypt.Hash import Hasher, HashAlgorithms


class ProfileManager:
    CURRENT_HASHED_USERNAME: Bytes
    CURRENT_HASHED_PASSWORD: Bytes

    @staticmethod
    def create_profile(username: Str, password: Str, *, silent: bool = False) -> None:
        hashed_username = Hasher.hash(username.encode(), HashAlgorithms.SHA3_256())
        hashed_password = Hasher.hash(password.encode(), HashAlgorithms.SHA3_256())

        current_profiles = json.load(open("profiles.json", "rb"))
        if username in current_profiles and not silent:
            logging.error("Profile already exists")
            return

        elif username in current_profiles and silent:
            ProfileManager.switch_profile(username, password)

        else:
            ports = [int(current_profiles[profile]["port"]) for profile in current_profiles]
            port = min(set(range(min(ports), max(ports) + 2)) - set(ports))
            current_profiles[username] = {"username": username, "password": hashed_password.hex(), "port": port, "current": False}
            json.dump(current_profiles, open("profiles.json", "w"))
            ProfileManager.switch_profile(username, password)

    @staticmethod
    def switch_profile(username: Str, password: Str) -> None:
        hashed_username = Hasher.hash(username.encode(), HashAlgorithms.SHA3_256())
        hashed_password = Hasher.hash(password.encode(), HashAlgorithms.SHA3_256())

        current_profiles = json.load(open("profiles.json", "rb"))
        if username not in current_profiles:
            logging.error("Username doesn't exist")
            return

        if hashed_password.hex() != current_profiles[username]["password"]:
            logging.error("Incorrect password")
            return

        for _, profile in current_profiles.items():
            profile["current"] = False
        current_profiles[username]["current"] = True

        json.dump(current_profiles, open("profiles.json", "w"))

        ProfileManager.CURRENT_HASHED_USERNAME = hashed_username
        ProfileManager.CURRENT_HASHED_PASSWORD = hashed_password

    @staticmethod
    def print_current_profile() -> None:
        current_profiles = json.load(open("profiles.json", "rb"))
        for username, profile in current_profiles.items():
            if profile["current"]:
                print(f"Current Profile: {username}")
                return
        logging.error("No current profile set")

    @staticmethod
    def list_all_profiles() -> None:
        current_profiles = json.load(open("profiles.json", "rb"))
        for username, profile in current_profiles.items():
            print(f"Profile: {username}" + (" (Current)" if profile["current"] else ""))
