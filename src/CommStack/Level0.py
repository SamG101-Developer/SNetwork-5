import pickle
import os
import time
from enum import Enum
from ipaddress import IPv6Address
from socket import socket as Socket, AF_INET6, SOCK_DGRAM, SHUT_RDWR
from threading import Thread

from src.CommStack.LevelN import LevelN, LevelNProtocol
from src.Utils.Atomic import AtomicInt
from src.Utils.Types import Dict, Int, List, Optional, Str, Bytes, Bool, Float
from src.DNet.DHash import DHash


class Level0State(Enum):
    STOP = 0
    ONLINE = 1


class Level0Protocol(Enum, LevelNProtocol):
    DNET_PING = 0
    DNET_LOOKUP_OR_PREV = 1
    DNET_LOOKUP_OR_NEXT = 2
    DNET_LOOKUP_FOUND = 3
    DNET_GET_NEIGHBOURS = 4
    DNET_GET_NEIGHBOURS_RESPONSE = 5
    DNET_UPDATE_PREV = 6
    DNET_UPDATE_NEXT = 7
    DNET_FILE = 8
    DNET_FILE_REQUEST = 9
    DNET_BACKUP_CLEAR = 10
    DNET_MIGRATE_DATA = 11
    DNET_FILE_BACKUP = 12


class Level0(LevelN):
    _state: Level0State
    _key: Int

    _prev_node: IPv6Address
    _next_node: IPv6Address
    _this_node: IPv6Address

    _heartbeat_interval: Float
    _prev_node_pings: AtomicInt
    _next_node_pings: AtomicInt
    _socket: Socket

    _files: List[Str]
    _backup_files: List[Str]
    _key_owners: Dict[Int, IPv6Address]
    _directory: Str

    def __init__(self):
        # General attributes.
        this_node = IPv6Address("::1")
        self._state = Level0State.STOP
        self._key = DHash.hash_address(this_node)

        # Node oriented attributes.
        self._prev_node = this_node
        self._next_node = this_node
        self._this_node = this_node

        # Network oriented attributes.
        self._heartbeat_interval = 0.5
        self._prev_node_pings = AtomicInt(0)
        self._next_node_pings = AtomicInt(0)
        self._socket = Socket(AF_INET6, SOCK_DGRAM)

        # File oriented attributes.
        self._files = []
        self._backup_files = []
        self._key_owners = {}
        self._directory = "_store"

        if not os.path.exists(self._directory):
            os.makedirs(self._directory)

        # Start threads.
        Thread(target=self._listen).start()
        Thread(target=self._ping_prev_node).start()
        Thread(target=self._ping_next_node).start()

    def join(self, joining_address: IPv6Address) -> None:
        # Send a lookup message to the joining node.
        self._send_message(joining_address, Level0Protocol.DNET_LOOKUP_OR_NEXT, {"key": self._key})

        while self._key not in self._key_owners:
            pass
        address = self._key_owners.get(self._key)

        # Get the neighbours of the joining node.
        self._send_message(address, Level0Protocol.DNET_GET_NEIGHBOURS)
        while self._next_node == self._this_node:
            pass

        # Update the previous and next nodes of the joining node.
        self._send_message(self._prev_node, Level0Protocol.DNET_UPDATE_NEXT)
        self._send_message(self._next_node, Level0Protocol.DNET_UPDATE_PREV)

        # Handle file location changes
        self._send_message(self._next_node, Level0Protocol.DNET_BACKUP_CLEAR)
        self._send_message(self._next_node, Level0Protocol.DNET_MIGRATE_DATA)

    def leave(self) -> None:
        # Send all files to the next node.
        for file in self._files:
            self._send_file(self._next_node, file)

        # Update the previous and next nodes of the next and previous nodes.
        self._send_message(self._next_node, Level0Protocol.DNET_UPDATE_PREV, {"address": self._prev_node})
        self._send_message(self._prev_node, Level0Protocol.DNET_UPDATE_NEXT, {"address": self._next_node})
        self._state = Level0State.STOP

    def kill(self) -> None:
        self._state = Level0State.STOP

    def get(self, file_name: Str) -> Bytes:
        file_key = DHash.hash(file_name.encode())
        if self._file_in_domain(file_key) and file_name in self._files:
            return open(os.path.join(self._directory, file_name), "rb").read()

        self._send_message(self._next_node, Level0Protocol.DNET_LOOKUP_OR_PREV, {"key": file_key})
        while file_key not in self._key_owners:
            pass
        receiver = self._key_owners.get(file_key)
        self._send_message(receiver, Level0Protocol.DNET_FILE_REQUEST, {"file_name": file_name})

        while not os.path.exists(file_name):
            time.sleep(1)

        return open(os.path.join(self._directory, file_name), "rb").read()

    def put(self, file_name: Str) -> None:
        file_key = DHash.hash(file_name.encode())

        # If the file is in the domain of the current node, save it.
        if self._file_in_domain(file_key):
            self._put_file(file_name)
            self._reg_file(file_name)
            return

        # Otherwise, send the file to the node whose domain it is in.
        self._send_message(self._next_node, Level0Protocol.DNET_LOOKUP_OR_PREV, {"key": file_key})

        while file_key not in self._key_owners:
            pass
        receiver = self._key_owners.get(file_key)
        self._send_file(receiver, file_name)

    def _node_in_domain(self, key: Int) -> Bool:
        next_node_key = DHash.hash_address(self._next_node)
        t1 = next_node_key == self._key
        t2 = next_node_key < self._key and (key >= self._key or key < next_node_key)
        t3 = next_node_key > self._key and self._key < key <= next_node_key
        return t1 or t2 or t3

    def _file_in_domain(self, key: Int) -> Bool:
        prev_node_key = DHash.hash_address(self._prev_node)
        t1 = prev_node_key == self._key
        t2 = prev_node_key > self._key and (key < self._key or key >= prev_node_key)
        t3 = prev_node_key < self._key and self._key >= key > prev_node_key
        return t1 or t2 or t3

    def _listen(self) -> None:
        # Bind the socket to the node's address.
        self._socket.bind((self._this_node.exploded, self._port))
        self._state = Level0State.ONLINE

        # Keep listening whilst the node is online.
        while self._state == Level0State.ONLINE and self._state == Level0State.ONLINE:
            try:
                data, address = self._socket.recvfrom(1024)
                data = pickle.loads(data)
                Thread(target=self._handle_command, args=(IPv6Address(address[0]), data)).start()
            except ConnectionResetError:
                break

        # Clean up.
        self._socket.shutdown(SHUT_RDWR)
        self._socket.close()

    def _ping_prev_node(self) -> None:
        # Keep pinging whilst the node is online.
        while self._state == Level0State.ONLINE:
            # Wait for the previous node to be set.
            while self._prev_node == self._this_node:
                time.sleep(self._heartbeat_interval)

            # If there is a previous node, and it is still responsive, keep pinging it.
            while self._state == Level0State.ONLINE and self._prev_node_pings.get() < 3:
                time.sleep(self._heartbeat_interval)
                self._send_message(self._prev_node, Level0Protocol.DNET_PING)
                self._prev_node_pings.inc()

            # The node has become unresponsive, so remove it from the network.
            self._prev_node = self._this_node
            self._prev_node_pings.set(0)

            # Handle files.
            self._backup_restore()
            self._send_file_backups(self._next_node)

            # Handle node switching.
            self._send_message(self._next_node, Level0Protocol.DNET_LOOKUP_OR_NEXT, {"key": self._key})
            while self._next_node == self._this_node or self._key not in self._key_owners:
                pass
            self._prev_node = self._key_owners.get(self._key)
            self._send_message(self._prev_node, Level0Protocol.DNET_UPDATE_NEXT)

    def _ping_next_node(self) -> None:
        # Keep pinging whilst the node is online.
        while self._state == Level0State.ONLINE:
            # Wait for the next node to be set.
            while self._next_node == self._this_node:
                time.sleep(self._heartbeat_interval)

            # If there is a next node, and it is still responsive, keep pinging it.
            while self._next_node_pings.get() < 3:
                time.sleep(self._heartbeat_interval)
                self._send_message(self._next_node, Level0Protocol.DNET_PING)
                self._next_node_pings.inc()

            # The node has become unresponsive, so remove it from the network.
            self._next_node = self._this_node
            self._next_node_pings.set(0)

    def _put_file(self, file_name: Str) -> None:
        data = open(file_name, "rb").read()
        open(os.path.join(self._directory, file_name), "wb").write(data)

    def _reg_file(self, file_name: Str) -> None:
        self._files.append(file_name)
        self._send_file_backups(self._next_node)

    @property
    def _port(self) -> Int:
        return 40000

    def _handle_command(self, address: IPv6Address, data: Dict) -> None:
        match Level0Protocol(data.get("cmd")):
            case Level0Protocol.DNET_PING if address == self._prev_node:
                self._handle_ping_from_prev_node(address)
            case Level0Protocol.DNET_PING if address == self._next_node:
                self._handle_ping_from_next_node(address)
            case Level0Protocol.DNET_LOOKUP_OR_PREV:
                self._lookup_key_in_domain_or_prev(address, data.get("send_to", address), data.get("key"))
            case Level0Protocol.DNET_LOOKUP_OR_NEXT:
                self._lookup_key_in_domain_or_next(address, data.get("send_to", address), data.get("key"))
            case Level0Protocol.DNET_LOOKUP_FOUND:
                self._handle_lookup_found(address, data.get("key"))
            case Level0Protocol.DNET_GET_NEIGHBOURS:
                self._handle_get_neighbours(address)
            case Level0Protocol.DNET_GET_NEIGHBOURS_RESPONSE:
                self._handle_get_neighbours_response(address, data.get("prev"), data.get("next"))
            case Level0Protocol.DNET_FILE_REQUEST:
                self._handle_file_request(address, data.get("file_name"))
            case Level0Protocol.DNET_FILE:
                self._handle_file(address, data.get("file_name"), data.get("file_bytes"))
            case Level0Protocol.DNET_FILE_BACKUP:
                self._handle_backup_file(address, data.get("file_name"), data.get("file_bytes"))
            case Level0Protocol.DNET_UPDATE_PREV:
                self._prev_node = data.get("address", address)
            case Level0Protocol.DNET_UPDATE_NEXT:
                self._next_node = data.get("address", address)
                self._send_file_backups(self._next_node)
            case Level0Protocol.DNET_BACKUP_CLEAR:
                self._backup_clear()
            case Level0Protocol.DNET_MIGRATE_DATA:
                self._handle_migration(address)

    def _handle_ping_from_prev_node(self, address: IPv6Address) -> None:
        # Reset the ping count of the previous node.
        assert self._prev_node == address
        self._prev_node_pings.set(0)

    def _handle_ping_from_next_node(self, address: IPv6Address) -> None:
        # Reset the ping count of the next node.
        assert self._next_node == address
        self._next_node_pings.set(0)

    def _lookup_key_in_domain_or_prev(self, address: IPv6Address, send_to: IPv6Address, key: Int) -> None:
        # Check if the key is in the domain of the current node.
        if self._file_in_domain(key):
            self._send_message(send_to, Level0Protocol.DNET_LOOKUP_FOUND, {"key": key})
            return

        # Otherwise, check if the key is in the domain of the previous node.
        self._send_message(self._prev_node, Level0Protocol.DNET_LOOKUP_OR_PREV, {"send_to": send_to, "key": key})

    def _lookup_key_in_domain_or_next(self, address: IPv6Address, send_to: IPv6Address, key: Int) -> None:
        # Check if the key is in the domain of the current node.
        if self._node_in_domain(key):
            self._send_message(send_to, Level0Protocol.DNET_LOOKUP_FOUND, {"key": key})
            return

        # Otherwise, check if the key is in the domain of the next node.
        self._send_message(self._next_node, Level0Protocol.DNET_LOOKUP_OR_NEXT, {"send_to": send_to, "key": key})

    def _handle_lookup_found(self, address: IPv6Address, key: Int) -> None:
        # If the key is found, add it to the list of key owners.
        self._key_owners[key] = address

    def _handle_get_neighbours(self, address: IPv6Address) -> None:
        # Send the neighbours of the current node to the requesting node.
        self._send_message(address, Level0Protocol.DNET_GET_NEIGHBOURS_RESPONSE, {"prev": self._this_node, "next": self._next_node})

    def _handle_get_neighbours_response(self, address: IPv6Address, prev: IPv6Address, next: IPv6Address) -> None:
        # Set the previous and next nodes of the current node.
        self._prev_node = prev
        self._next_node = next

    def _handle_file_request(self, address: IPv6Address, file_name: Str) -> None:
        # Send the file to the requesting node.
        file_bytes = open(os.path.join(self._directory, file_name), "rb").read()
        self._send_message(address, Level0Protocol.DNET_FILE, {"file_name": file_name, "file_bytes": file_bytes})

    def _handle_file(self, address: IPv6Address, file_name: Str, file_bytes: Bytes) -> None:
        # Save the file to the current node.
        self._reg_file(file_name)
        open(os.path.join(self._directory, file_name), "wb").write(file_bytes)

    def _handle_backup_file(self, address: IPv6Address, file_name: Str, file_bytes: Bytes) -> None:
        # Save the file to the current node.
        open(os.path.join(self._directory, file_name), "wb").write(file_bytes)
        self._backup_files.append(file_name)

    def _handle_migration(self, address: IPv6Address) -> None:
        self._prev_node = address
        files_to_send = [file_name for file_name in self._files if not self._file_in_domain(DHash.hash(file_name.encode()))]
        for file_name in files_to_send:
            self._send_file(address, file_name)
            self._files.remove(file_name)

        self._send_file_backups(self._next_node)

    def _backup_restore(self) -> None:
        self._files[-1:] = self._backup_files.copy()
        self._backup_files.clear()

    def _backup_clear(self) -> None:
        self._backup_files.clear()

    def _send_message(self, address: IPv6Address, protocol: Level0Protocol, data: Optional[Dict] = None) -> None:
        data = pickle.dumps({"cmd": protocol.value, **(data or {})})
        if self._state == Level0State.ONLINE:
            self._socket.sendto(data, (address.exploded, self._port))

    def _send_file(self, address: IPv6Address, file_name: Str) -> None:
        data = open(file_name, "rb").read()
        self._send_message(address, Level0Protocol.DNET_FILE, {"file_name": file_name, "file_bytes": data})

    def _send_file_backups(self, address: IPv6Address) -> None:
        self._send_message(address, Level0Protocol.DNET_BACKUP_CLEAR)
        for file_name in self._backup_files:
            self._send_file_backup(address, file_name)

    def _send_file_backup(self, address: Optional[IPv6Address], file_name: Str) -> None:
        if address == self._this_node: return
        data = open(file_name, "rb").read()
        self._send_message(address, Level0Protocol.DNET_FILE_BACKUP, {"file_name": file_name, "file_bytes": data})
