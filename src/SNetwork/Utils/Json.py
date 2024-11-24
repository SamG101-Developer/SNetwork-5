import json

from SNetwork.Utils.Types import Bytes, Str, Json, Callable, Optional


class SafeJson:
    @staticmethod
    def loads(string: Bytes | Str, error_handler: Optional[Callable[[], None]] = None) -> Json:
        try:
            string = string.decode() if isinstance(string, bytes) else string
            string = string.replace("'", "\"")
            return json.loads(string)
        except json.JSONDecodeError:
            error_handler and error_handler()
            return {}

    @staticmethod
    def dumps(data: Json, error_handler: Optional[Callable[[], None]] = None) -> Bytes:
        try:
            return json.dumps(data).encode()
        except TypeError as e:
            error_handler and error_handler()
            return b"{}"
