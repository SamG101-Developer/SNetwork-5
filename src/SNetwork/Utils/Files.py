from filelock import FileLock


class SafeFileOpen:
    """
    Thread-safe file open and auto-close.
    """

    def __init__(self, file_path: str, mode: str):
        self._file_path = file_path
        self._mode = mode
        self._file = None
        self._lock = FileLock(f"{file_path}.lock")

    def __enter__(self):
        self._lock.acquire()
        self._file = open(self._file_path, self._mode)
        return self._file

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._file.close()
        self._lock.release()
