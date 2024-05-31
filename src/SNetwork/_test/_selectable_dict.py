
import time

import select
import socket
from threading import Thread, Condition, Event

from SNetwork.Utils.Types import Int, Bool, Dict


class Selectable[K, V]:
    _key: K
    _condition: Condition
    _ready: Event
    _rsock: socket.socket
    _wsock: socket.socket

    def __init__(self, key: K, condition: Condition) -> None:
        self._key = key
        self._condition = condition
        self._ready = Event()
        self._rsock, self._wsock = socket.socketpair()

    def set_value(self, value: V) -> None:
        with self._condition:
            if not self._ready.is_set():
                self._wsock.sendall(str(value).encode())
                self._ready.set()

    def fileno(self) -> Int:
        return self._rsock.fileno()

    def close(self) -> None:
        self._rsock.close()
        self._wsock.close()


class SelectableDict[K, V]:
    _dict: Dict[K, V]
    _conditions: Dict[K, Condition]
    _selectables: Dict[K, Selectable[K, V]]

    def __init__(self) -> None:
        self._dict = {}
        self._conditions = {}
        self._selectables = {}

    def __getitem__(self, key: K) -> Selectable[K, V]:
        if key not in self._conditions:
            self._conditions[key] = Condition()
        if key not in self._selectables:
            self._selectables[key] = Selectable(key, self._conditions[key])
        return self._selectables[key]

    def __setitem__(self, key: K, value: V) -> None:
        if key not in self._conditions:
            self._conditions[key] = Condition()
        with self._conditions[key]:
            self._dict[key] = value
            if key in self._selectables:
                self._selectables[key].set_value(value)
            self._conditions[key].notify_all()

    def __delitem__(self, key: K) -> None:
        if key in self._dict:
            del self._dict[key]
        if key in self._conditions:
            with self._conditions[key]:
                self._conditions[key].notify_all()
                del self._conditions[key]
        if key in self._selectables:
            self._selectables[key].close()
            del self._selectables[key]

    def __contains__(self, key: K) -> Bool:
        return key in self._dict

    def __len__(self) -> Int:
        return len(self._dict)

    def __repr__(self):
        return str(self._dict)


def fill[K, V](d0: SelectableDict[K, V], d1: SelectableDict[K, V]) -> None:
    time.sleep(1)
    d0["key"] = "value"


def test_selectable_dict() -> None:
    d0 = SelectableDict()
    d1 = SelectableDict()

    thread = Thread(target=fill, args=(d0, d1))
    thread.start()

    while True:
        readable, _, _ = select.select([d0["key"], d1["key"]], [], [], 0.1)
        if readable:
            for r in readable:
                if isinstance(r, Selectable):
                    print(r._key, r._rsock.recv(1024).decode())
                    r.close()
                    return
        else:
            print("No data yet.")


test_selectable_dict()
