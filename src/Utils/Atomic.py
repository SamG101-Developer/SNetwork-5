from threading import Lock
from src.Utils.Types import Int


class AtomicInt:
    _value: Int
    _lock: Lock

    def __init__(self, value: Int = 0) -> None:
        self._value = value
        self._lock = Lock()

    def inc(self, i: Int = 1) -> Int:
        with self._lock:
            self._value += i
            return self._value

    def dec(self, i: Int = 1) -> Int:
        with self._lock:
            self._value -= i
            return self._value

    def get(self) -> Int:
        with self._lock:
            return self._value

    def set(self, value: Int) -> None:
        with self._lock:
            self._value = value
