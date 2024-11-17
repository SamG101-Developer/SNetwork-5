import hashlib
import hmac
import secrets


class SharedCSPRNG:
    def __init__(self, init_key: bytes, personalization_string: bytes) -> None:
        self._key = init_key
        self._personalization_string = personalization_string
        self._state = init_key
        self._counter = 0

    def _update_state(self) -> None:
        data = self._state + self._counter.to_bytes(8, "big") + self._personalization_string
        self._state = hmac.new(self._key, data, hashlib.sha256).digest()

    def get_random_bytes(self, num_bytes: int) -> bytes:
        result = b""
        self._counter += 1
        while len(result) < num_bytes:
            self._update_state()
            result += self._state
        return result[:num_bytes]


if __name__ == "__main__":
    K = secrets.token_bytes(32)
    gen_a = SharedCSPRNG(K, b"")
    gen_b = SharedCSPRNG(K, b"")

    print("Key 1")
    print("A", gen_a.get_random_bytes(32).hex())
    print("B", gen_b.get_random_bytes(32).hex())

    print("Key 2")
    print("A", gen_a.get_random_bytes(32).hex())
    print("B", gen_b.get_random_bytes(32).hex())
