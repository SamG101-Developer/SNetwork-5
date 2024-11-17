from SNetwork.Utils.Types import Bytes, Dict


class ParserHttp:
    _http: Bytes

    def __init__(self, http: Bytes) -> None:
        self._http = http

    @property
    def method(self) -> Bytes:
        return self._http.split(b" ")[0]

    @property
    def path(self) -> Bytes:
        return self._http.split(b" ")[1]

    @property
    def version(self) -> Bytes:
        return self._http.split(b" ")[2]

    @property
    def headers(self) -> Dict[Bytes, Bytes]:
        headers = {}
        for line in self._http.split(b"\r\n")[1:]:
            key, value = line.split(b": ")
            headers[key] = value
        return headers
