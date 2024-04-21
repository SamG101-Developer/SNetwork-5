import random
import time
import uuid
from ipaddress import IPv6Address

from DNet.DHash import DHash
from Comms.Level0 import Level0, DNodeAddress
from src.Utils.Types import List, Tuple


def test_init() -> Tuple[List[Level0], List[int]]:
    num = 5
    start_port = 49000
    ports = range(start_port, start_port + num)
    nodes = [Level0(DNodeAddress(ip=IPv6Address("::1"), port=port)) for port in ports]
    print("Nodes created")
    return nodes, [*ports]


def test_join(nodes: List[Level0]) -> None:
    nodes[1].join(nodes[0]._this_node)
    nodes[2].join(nodes[0]._this_node)
    nodes[3].join(nodes[0]._this_node)
    nodes[4].join(nodes[1]._this_node)
    time.sleep(2)

    nodes.sort(key=lambda node: node._key, reverse=False)

    for node_num in range(len(nodes)):
        try:
            assert nodes[node_num]._next_node == nodes[(node_num + 1) % len(nodes)]._this_node
            assert nodes[node_num]._prev_node == nodes[(node_num - 1) % len(nodes)]._this_node
        except AssertionError:
            print("Error in node", node_num)
            print(nodes[node_num]._next_node)
            print(nodes[(node_num + 1) % len(nodes)]._this_node)
            print(nodes[node_num]._prev_node)
            print(nodes[(node_num - 1) % len(nodes)]._this_node)


def test_put_and_get(nodes: List[Level0]) -> List[str]:
    files = [f"dummy_{uuid.uuid4()}.txt" for i in range(8)]
    for file_name in files:
        open(file_name, "w").write(uuid.uuid4().hex)

    file_keys = []
    for file_name in files:
        file_key = DHash.hash(file_name.encode())
        file_keys.append(file_key)
        nodes[0].put(file_name)

    time.sleep(3)

    for i in range(len(files)):
        for j in range(len(nodes)):
            if (nodes[j]._key >= file_keys[i] > nodes[j - 1]._key) or (file_keys[i] > nodes[-1]._key and j == 0):
                assert files[i] in nodes[j]._files

    print("Files put successfully")

    random_file = random.choice(files)
    for node in nodes:
        node.get(random_file)

    return files


def test_rehash(nodes: List[Level0], files: List[str], port: int) -> None:
    new_ports = [port + i for i in range(3)]
    for new_port in new_ports:
        new_node = Level0(DNodeAddress(ip=IPv6Address("::1"), port=new_port))
        new_node.join(nodes[0]._this_node)
        print(f"Node {new_node._this_node._port} joined")
        nodes.append(new_node)
    time.sleep(2)

    nodes.sort(key=lambda node: node._key, reverse=False)
    print("Nodes", [node._this_node._port for node in nodes])

    file_hashes = []
    for file in files:
        file_hashes.append(DHash.hash(file.encode()))

    for i in range(len(files)):
        for j in range(len(nodes)):
            if nodes[j]._key >= file_hashes[i] > nodes[j - 1]._key or file_hashes[i] > nodes[-1]._key and i == 0:
                assert files[i] in nodes[j]._files

    print("Files rehashed successfully")
    time.sleep(3)


def test_leave(nodes: List[Level0], files: List[str]) -> None:
    random_file = random.choice(files)
    for i in range(len(nodes)):
        if random_file in nodes[i]._files:
            break

    print(nodes)
    nodes[i].leave()
    print(f"Node {nodes[i]._this_node._port} leaving")
    print(f"For file {random_file}")
    time.sleep(3)
    del nodes[i]
    print("Node left")

    for i in range(len(nodes)):
        try:
            assert nodes[i]._next_node == nodes[(i + 1) % len(nodes)]._this_node
            assert nodes[i]._prev_node == nodes[(i - 1) % len(nodes)]._this_node
        except AssertionError:
            print("Error in node", i)
            print(nodes[i]._next_node)
            print(nodes[(i + 1) % len(nodes)]._this_node)
            print(nodes[i]._prev_node)
            print(nodes[(i - 1) % len(nodes)]._this_node)

    print("Node left successfully")
    print(nodes[i % len(nodes)]._this_node._port, nodes[i % len(nodes)]._files)

    assert random_file in nodes[i % len(nodes)]._files
    print("File transferred successfully")


def exit_nodes(nodes) -> None:
    for node in nodes:
        node.kill()


def main():
    nodes, ports = test_init()
    test_join(nodes)
    files = test_put_and_get(nodes)
    test_rehash(nodes, files, max(ports) + 1)
    test_leave(nodes, files)

    print("done")
    while True:
        try:
            pass
        except KeyboardInterrupt:
            exit_nodes(nodes)
            break


if __name__ == "__main__":
    main()
