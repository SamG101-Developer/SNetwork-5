import json

from SNetwork.Utils.Types import Bytes, Str, Json, Callable, Optional


class SafeJson:
    @staticmethod
    def loads(string: Bytes | Str, error_handler: Optional[Callable[[...], None]] = None) -> Json:
        try:
            return json.loads(string)
        except json.JSONDecodeError:
            error_handler and error_handler()
            return {}

    @staticmethod
    def dumps(data: Json, error_handler: Optional[Callable[[...], None]] = None) -> Bytes:
        try:
            return json.dumps(data).encode()
        except TypeError:
            error_handler and error_handler()
            return b"{}"
