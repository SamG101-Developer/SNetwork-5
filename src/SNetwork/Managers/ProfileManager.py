import json
import logging
import os

from SNetwork.Config import PROFILE_FILE, PROFILE_CACHE
from SNetwork.Managers.KeyManager import KeyStoreData, KeyManager
from SNetwork.QuantumCrypto.Certificate import X509
from SNetwork.QuantumCrypto.Hash import Hasher, HashAlgorithm
from SNetwork.QuantumCrypto.Keys import AsymmetricKeyPair
from SNetwork.QuantumCrypto.QuantumSign import QuantumSign
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Types import Bytes, Int, Optional, Tuple
from SNetwork.Utils.Types import Str, List, Dict


class ProfileManager:
    @staticmethod
    def create_profile(username: Str, password: Str) -> None:
        # Hash the username and password.
        hashed_username = Hasher.hash(username.encode(), HashAlgorithm.SHA3_256)
        hashed_password = Hasher.hash(password.encode(), HashAlgorithm.SHA3_256)
        current_profiles = ProfileManager._load_current_profiles()

        # Check if the username already exists
        if username in current_profiles:
            logging.error("Profile already exists")
            return

        # Get the next available port from the current profiles, and update the JSON file.
        else:
            ports = [int(current_profile["port"]) for current_profile in current_profiles.values()] or [40000]
            port = min(set(range(min(ports), max(ports) + 2)) - set(ports))
            current_profiles[username] = {
                "username": username,
                "hashed_username": hashed_username.hex(),
                "hashed_password": hashed_password.hex(),
                "port": port}

            with SafeFileOpen(PROFILE_FILE, "w") as file:
                json.dump(current_profiles, file)

        # Create the profile cache file.
        with SafeFileOpen(PROFILE_CACHE % hashed_username.hex(), "w") as file:
            json.dump({}, file)

        # Key and certificate information, ands et information into the keyring.
        static_key_pair = QuantumSign.generate_key_pair()
        identifier = Hasher.hash(static_key_pair.public_key, HashAlgorithm.SHA3_256)
        ProfileManager._generate_profile_certificate(hashed_username, hashed_password, identifier, static_key_pair, port)

    @staticmethod
    def delete_profile(username: Str, password: Str) -> None:
        # Hash the username and password.
        current_profiles = ProfileManager._load_current_profiles()
        hashed_username = Hasher.hash(username.encode(), HashAlgorithm.SHA3_256)
        if not ProfileManager.validate_profile(username, password): return

        # Delete the profile from the JSON file.
        del current_profiles[username]
        with SafeFileOpen(PROFILE_FILE, "w") as file:
            json.dump(current_profiles, file)

        # Delete the profile cache file.
        os.remove(PROFILE_CACHE % hashed_username.hex())

    @staticmethod
    def validate_profile(username: Str, password: Str) -> Optional[Tuple[Bytes, Bytes, Int]]:
        # Hash the username and password.
        hashed_username = Hasher.hash(username.encode(), HashAlgorithm.SHA3_256)
        hashed_password = Hasher.hash(password.encode(), HashAlgorithm.SHA3_256)
        current_profiles = ProfileManager._load_current_profiles()

        # Check if the username exists.
        if username not in current_profiles:
            logging.error("Username doesn't exist")
            return None

        # Check if the password is correct.
        if hashed_password.hex() != current_profiles[username]["hashed_password"]:
            logging.error("Incorrect password")
            return None

        # Set the cache to "{}" if the file is empty or doesn't exist.
        if not os.path.exists(PROFILE_CACHE % hashed_username.hex()) or os.path.getsize(PROFILE_CACHE % hashed_username.hex()) == 0:
            with SafeFileOpen(PROFILE_CACHE % hashed_username.hex(), "w") as file:
                json.dump({}, file)

        # Return the hashed username and port.
        return hashed_username, hashed_password, current_profiles[username]["port"]

    @staticmethod
    def list_usernames_formatted() -> List[Str]:
        # Load the current profiles and print them.
        current_profiles = ProfileManager._load_current_profiles()
        return [("🔒" if ProfileManager._has_password(username) else "🔓") + username for username in current_profiles]

    @staticmethod
    def _generate_profile_certificate(
            hashed_username: Bytes, hashed_password: Bytes, identifier: Bytes, static_key_pair: AsymmetricKeyPair,
            port: Int) -> None:

        # Generate the certificate signing request.
        certificate_signing_request = X509.generate_certificate_signing_request(
            client_identifier=identifier,
            client_secret_key=static_key_pair.secret_key,
            client_public_key=static_key_pair.public_key,
            signer_identifier=identifier)

        # Generate the certificate from the signing request.
        certificate = X509.generate_certificate(
            client_signing_request=certificate_signing_request,
            client_identifier=identifier,
            directory_service_key_pair=static_key_pair,
            signer_identifier=identifier)

        # Store the certificate and other information in the key store.
        KeyManager.set_info(KeyStoreData(
            identifier=identifier,
            secret_key=static_key_pair.secret_key,
            public_key=static_key_pair.public_key,
            certificate=certificate,
            hashed_username=hashed_username,
            hashed_password=hashed_password,
            port=port))

    @staticmethod
    def _load_current_profiles() -> Dict:
        # Load the current profiles.
        with SafeFileOpen(PROFILE_FILE, "rb") as file:
            current_profiles = json.load(file)
        return current_profiles

    @staticmethod
    def _has_password(username: str) -> bool:
        # Load the current profiles.
        with SafeFileOpen(PROFILE_FILE, "rb") as file:
            current_profiles = json.load(file)
        hashed_default_password = Hasher.hash(b"", HashAlgorithm.SHA3_256).hex()
        return current_profiles[username]["hashed_password"] != hashed_default_password
