from hashlib import sha256
from threading import Thread

from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
from SNetwork.Managers.ProfileManager import ProfileManager

NODE_COUNT = 10


def run_node(node_id: int) -> None:
    username, password = (f"username-{node_id}", "")
    ProfileManager.create_profile(username, password)
    ProfileManager.switch_profile(username, password)
    communication_stack = CommunicationStack(is_directory_node=False)


def main():
    threads = []
    for i in range(NODE_COUNT):
        thread = Thread(target=run_node, args=(i,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
