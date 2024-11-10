import os.path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from argparse import ArgumentParser
from argformat.formatter import StructuredFormatter

from SNetwork.Boot.CommandHandler import CommandHandler


class ErrorArgumentParser(ArgumentParser):
    def error(self, message: str) -> None:
        print(f"\nError: {message}")
        self.print_help()
        print("\n")
        sys.exit(2)


def create_argument_parser() -> ArgumentParser:
    parser = ErrorArgumentParser(prog="snetwork", description="A distributed anonymous overlay network", formatter_class=StructuredFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Profile Parser
    profile_manager_parser = subparsers.add_parser("profiles", help="Manage profiles using the network")
    profile_manager_subparsers = profile_manager_parser.add_subparsers(dest="profile_command", required=True, help="Available profile commands")

    profile_manager_create_profile = profile_manager_subparsers.add_parser("create", help="Create a new profile")
    profile_manager_create_profile.add_argument("--name", type=str, required=True, help="Name of profile", dest="username")
    profile_manager_create_profile.add_argument("--pass", type=str, help="Password of profile", dest="password")

    profile_manager_switch_profile = profile_manager_subparsers.add_parser("switch", help="Switch to a existing profile")
    profile_manager_switch_profile.add_argument("--name", type=str, required=True, help="Name of profile", dest="username")
    profile_manager_switch_profile.add_argument("--pass", type=str, help="Password of profile", dest="password")

    profile_manager_current_profile = profile_manager_subparsers.add_parser("current", help="Display the current profile")

    profile_manager_list_profiles = profile_manager_subparsers.add_parser("list", help="List all profiles")

    # Join Parser
    join_parser = subparsers.add_parser("join", help="Join the network")

    # Directory Node Parser
    directory_node_parser = subparsers.add_parser("directory", help="Join the network as a directory node")

    # Exit Node Parser
    exit_node_parser = subparsers.add_parser("exit", help="Exit the network")

    # Clear Parser
    exit_node_parser = subparsers.add_parser("clear", help="Clear the terminal")

    return parser


def main() -> None:
    parser = create_argument_parser()
    args = parser.parse_args(sys.argv[1:])
    CommandHandler.handle_command(args.command, args)


if __name__ == "__main__":
    # Append folder to the system path to allow "from SNetwork" imports.
    main()
