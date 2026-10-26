"""HMAC по RFC 2104, написанный с нуля поверх собственных хэш-функций (MAC-1 .. MAC-5)."""
from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256

# имя алгоритма -> (класс хэш-функции, размер блока в байтах)
# у SHA-256 блок 64 байта, у SHA3-256 это rate губки Keccak: 136 байт
HASH_FUNCTIONS = {
    "sha256": (SHA256, 64),
    "sha3-256": (SHA3_256, 136),
}

IPAD_BYTE = 0x36
OPAD_BYTE = 0x5C


def get_hash_function(name):
    """Вернуть (класс хэша, размер блока) по имени алгоритма."""
    try:
        return HASH_FUNCTIONS[name]
    except KeyError:
        raise ValueError(f"HMAC does not support hash algorithm '{name}'")


class HMAC:
    """HMAC(K, m) = H((K xor opad) || H((K xor ipad) || m)).

    Работает потоково: update() можно вызывать много раз, поэтому файл
    любого размера обрабатывается порциями при постоянной памяти (MAC-5).
    Интерфейс update()/hexdigest() совпадает с хэшами проекта, поэтому
    файл считается той же функцией hash_file, что и обычный хэш.
    """

    def __init__(self, key, hash_function="sha256"):
        self.hash_class, self.block_size = get_hash_function(hash_function)
        self.key = self._process_key(bytes(key))
        self._ipad = self._xor_bytes(self.key, bytes([IPAD_BYTE]) * self.block_size)
        self._opad = self._xor_bytes(self.key, bytes([OPAD_BYTE]) * self.block_size)
        # внутренний хэш сразу «съедает» K xor ipad, дальше в него идёт сообщение
        self._inner = self._new_inner()

    def _process_key(self, key):
        # ключ длиннее блока заменяется своим хэшем (MAC-2)
        if len(key) > self.block_size:
            hasher = self.hash_class()
            hasher.update(key)
            key = hasher.digest()
        # ключ короче блока дополняется нулями справа до размера блока
        if len(key) < self.block_size:
            key = key + b"\x00" * (self.block_size - len(key))
        return key

    @staticmethod
    def _xor_bytes(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def _new_inner(self):
        inner = self.hash_class()
        inner.update(self._ipad)
        return inner

    def update(self, data):
        """Подать очередную порцию сообщения."""
        self._inner.update(data)

    def digest(self):
        """Итоговый HMAC в байтах; состояние объекта не меняется."""
        inner_hash = self._inner.digest()
        outer = self.hash_class()
        outer.update(self._opad + inner_hash)
        return outer.digest()

    def hexdigest(self):
        return self.digest().hex()

    def compute(self, message):
        """HMAC сообщения целиком (hex); не зависит от ранее поданных update()."""
        inner = self._new_inner()
        inner.update(message)
        outer = self.hash_class()
        outer.update(self._opad + inner.digest())
        return outer.hexdigest()
