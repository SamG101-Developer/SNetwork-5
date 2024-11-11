import os
from threading import Thread
from argparse import Namespace

from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
from SNetwork.Managers.KeyManager import KeyManager
from SNetwork.Managers.ProfileManager import ProfileManager
from SNetwork.Utils.Types import List, Str


class CommandHandler:
    THREADS: List[Thread] = []
    STACK: CommunicationStack

    @staticmethod
    def handle_command(command: Str, arguments: Namespace) -> None:
        target = getattr(CommandHandler, f"_handle_{str(command).lower()}")(arguments)
        thread = Thread(target=target, args=(arguments, ))
        thread.start()
        CommandHandler.THREADS.append(thread)

    @staticmethod
    def _handle_profiles(arguments: Namespace) -> None:
        match arguments.profile_command:
            case "create": ProfileManager.create_profile(arguments.username, arguments.password or "")
            case "switch": ProfileManager.switch_profile(arguments.username, arguments.password or "")
            case "current": ProfileManager.print_current_profile()
            case "list": ProfileManager.list_all_profiles()

    @staticmethod
    def _handle_clear(arguments: Namespace) -> None:
        os.system("cls")

    @staticmethod
    def _handle_directory(arguments: Namespace) -> None:
        ProfileManager.switch_profile("directory", "")
        comm_stack = CommunicationStack(is_directory_node=True)
        while True: continue

    @staticmethod
    def _handle_join(arguments: Namespace) -> None:
        comm_stack = CommunicationStack(is_directory_node=False)
        while True: continue

    @staticmethod
    def _handle_none(_) -> None:
        ...
