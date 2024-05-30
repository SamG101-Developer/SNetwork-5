import socket
from threading import Condition, Event
from socket import socket as Socket

from SNetwork.Utils.Types import Bool, Bytes, Int


class Selectable[K]:
    """
    The Selectable class is an object returned by the SelectableDict class. It is used to store a value that can be
    accessed by multiple threads, and waited on by the "select.select" function. This allows it to be used like a socket
    buffer with selection.

    Attributes:
        _key: The key of the value in the SelectableDict.
        _condition: The condition object used to synchronise access to the value.
        _ready: The event object used to signal that the value is ready.
        _r_sock: The read-socket used to signal that the value is ready.
        _w_sock: The write-socket used to signal that the value is ready.
    """

    _key: K
    _condition: Condition
    _ready: Event
    _r_sock: Socket
    _w_sock: Socket

    def __init__(self, key: K, condition: Condition) -> None:
        # Initialize the Selectable object.
        self._key = key
        self._condition = condition
        self._ready = Event()

        # Create a socket pair for the Selectable object.
        self._r_sock, self._w_sock = socket.socketpair()

    def set_value(self, value: Bytes) -> None:
        # Set the value of the Selectable object.
        with self._condition:
            if not self._ready.is_set():
                self._w_sock.sendall(value)
                self._ready.set()

    def fileno(self) -> int:
        # Return the file descriptor of the read socket.
        return self._r_sock.fileno()

    def close(self) -> None:
        # Close the read and write sockets.
        self._r_sock.close()
        self._w_sock.close()

    def setblocking(self, blocking: Bool) -> None:
        # Set the blocking mode of the read socket.
        self._r_sock.setblocking(blocking)

    def __del__(self) -> None:
        # Ensure the sockets are closed when the object is deleted.
        self.close()


class SelectableDict[K]:
    """
    The SelectableDict class is a specialised dictionary that stores Selectable objects. It can be waited on by using
    the "select.select" function. All objects returned are Selectable objects, which in turn wrap a value that can be
    accessed by multiple threads.

    Attributes:
        _dictionary: The dictionary used to store the values.
        _conditions: The dictionary used to store the conditions.
        _selectables: The dictionary used to store the Selectable objects.
    """

    _dictionary: dict[K, Bytes]
    _conditions: dict[K, Condition]
    _selectables: dict[K, Selectable[K]]

    def __init__(self) -> None:
        # Initialize the SelectableDict object.
        self._dict = {}
        self._conditions = {}
        self._selectables = {}

    def __getitem__(self, key: K) -> Selectable[K]:
        # Get the Selectable object for the key.
        if key not in self._conditions:
            self._conditions[key] = Condition()
        if key not in self._selectables:
            self._selectables[key] = Selectable(key, self._conditions[key])
        return self._selectables[key]

    def __setitem__(self, key: K, val: Bytes) -> None:
        # Set the value for the key.
        if key not in self._conditions:
            self._conditions[key] = Condition()
        with self._conditions[key]:
            self._dict[key] = val
            if key in self._selectables:
                self._selectables[key].set_value(val)
            self._conditions[key].notify_all()

    def __delitem__(self, key: K) -> None:
        # Delete the value for the key.
        if key in self._dict:
            del self._dict[key]
        if key in self._conditions:
            with self._conditions[key]:
                self._conditions[key].notify_all()
                del self._conditions[key]
        if key in self._selectables:
            self._selectables[key].close()
            del self._selectables[key]

    def __len__(self) -> Int:
        # Return the length of the dictionary.
        return len(self._dict)


# import time
#
# import select
# import socket
# from threading import Thread, Condition, Event
#
# from SNetwork.Utils.Types import Int, Bool, Dict
#
#
# class Selectable[K, V]:
#     _key: K
#     _condition: Condition
#     _ready: Event
#     _rsock: socket.socket
#     _wsock: socket.socket
#
#     def __init__(self, key: K, condition: Condition) -> None:
#         self._key = key
#         self._condition = condition
#         self._ready = Event()
#         self._rsock, self._wsock = socket.socketpair()
#
#     def set_value(self, value: V) -> None:
#         with self._condition:
#             if not self._ready.is_set():
#                 self._wsock.sendall(str(value).encode())
#                 self._ready.set()
#
#     def fileno(self) -> Int:
#         return self._rsock.fileno()
#
#     def close(self) -> None:
#         self._rsock.close()
#         self._wsock.close()
#
#
# class SelectableDict[K, V]:
#     _dict: Dict[K, V]
#     _conditions: Dict[K, Condition]
#     _selectables: Dict[K, Selectable[K, V]]
#
#     def __init__(self) -> None:
#         self._dict = {}
#         self._conditions = {}
#         self._selectables = {}
#
#     def __getitem__(self, key: K) -> Selectable[K, V]:
#         if key not in self._conditions:
#             self._conditions[key] = Condition()
#         if key not in self._selectables:
#             self._selectables[key] = Selectable(key, self._conditions[key])
#         return self._selectables[key]
#
#     def __setitem__(self, key: K, value: V) -> None:
#         if key not in self._conditions:
#             self._conditions[key] = Condition()
#         with self._conditions[key]:
#             self._dict[key] = value
#             if key in self._selectables:
#                 self._selectables[key].set_value(value)
#             self._conditions[key].notify_all()
#
#     def __delitem__(self, key: K) -> None:
#         if key in self._dict:
#             del self._dict[key]
#         if key in self._conditions:
#             with self._conditions[key]:
#                 self._conditions[key].notify_all()
#                 del self._conditions[key]
#         if key in self._selectables:
#             self._selectables[key].close()
#             del self._selectables[key]
#
#     def __contains__(self, key: K) -> Bool:
#         return key in self._dict
#
#     def __len__(self) -> Int:
#         return len(self._dict)
#
#     def __repr__(self):
#         return str(self._dict)
#
#
# def fill[K, V](d0: SelectableDict[K, V], d1: SelectableDict[K, V]) -> None:
#     time.sleep(1)
#     d0["key"] = "value"
#
#
# def test_selectable_dict() -> None:
#     d0 = SelectableDict()
#     d1 = SelectableDict()
#
#     thread = Thread(target=fill, args=(d0, d1))
#     thread.start()
#
#     while True:
#         readable, _, _ = select.select([d0["key"], d1["key"]], [], [], 0.1)
#         if readable:
#             for r in readable:
#                 if isinstance(r, Selectable):
#                     print(r._key, r._rsock.recv(1024).decode())
#                     r.close()
#                     return
#         else:
#             print("No data yet.")
#
#
# test_selectable_dict()
