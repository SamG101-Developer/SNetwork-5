from SNetwork.Nodes.Node import Node


class DirectoryNode(Node):
    def __init__(self) -> None:
        super().__init__(b"directory", b"", 0)
