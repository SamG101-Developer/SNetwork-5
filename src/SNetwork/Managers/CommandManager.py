import os
from argparse import Namespace

from SNetwork.Managers.DirectoryServiceManager import DirectoryServiceManager
from SNetwork.Nodes.DirectoryNode import DirectoryNode
from SNetwork.Nodes.Node import Node
from SNetwork.Managers.ProfileManager import ProfileManager
from SNetwork.Utils.Types import NoReturn, Str
from SNetwork.Utils.Decorators import no_return_interruptable


class CommandManager:
    @staticmethod
    def handle_command(command: Str, arguments: Namespace) -> None:
        target = getattr(CommandManager, f"_handle_{str(command).lower()}")
        target(arguments)

    @staticmethod
    def _handle_profiles(arguments: Namespace) -> None:
        match arguments.profile_command:
            case "create": ProfileManager.create_profile(arguments.username, arguments.password or "")
            case "delete": ProfileManager.delete_profile(arguments.username, arguments.password or "")
            case "list": print("\n".join(ProfileManager.list_usernames_formatted()))

    @staticmethod
    def _handle_clear(arguments: Namespace) -> None:
        os.system("cls")

    @staticmethod
    @no_return_interruptable
    def _handle_directory(arguments: Namespace) -> NoReturn:
        hashed_username, hashed_password, port, identifier, static_key_pair = DirectoryServiceManager.validate_directory_profile(arguments.username)
        directory_node = DirectoryNode(arguments.username, hashed_username, hashed_password, port, identifier, static_key_pair)
        while True: continue

    @staticmethod
    @no_return_interruptable
    def _handle_join(arguments: Namespace) -> NoReturn:
        hashed_username, hashed_password, port = ProfileManager.validate_profile(arguments.username, arguments.password)
        node = Node(hashed_username, hashed_password, port)
        while True: continue

    @staticmethod
    def _handle_none(_) -> None:
        ...
