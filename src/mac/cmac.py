"""AES-CMAC по NIST SP 800-38B (бонус MAC-6), поверх AES-примитива из прошлых спринтов."""
from src.modes.common import BLOCK_SIZE, new_block_cipher, xor_bytes

# константа Rb для 128-битного блока: x^128 = x^7 + x^2 + x + 1
RB = 0x87


def _double(block):
    """Умножение на x в поле GF(2^128): сдвиг влево на бит и, при выходе старшего бита, XOR с Rb."""
    value = int.from_bytes(block, "big") << 1
    if value >> 128:
        value = (value & ((1 << 128) - 1)) ^ RB
    return value.to_bytes(BLOCK_SIZE, "big")


class CMAC:
    """AES-CMAC; потоковый интерфейс как у HMAC: update() / digest() / hexdigest()."""

    def __init__(self, key):
        if len(key) != BLOCK_SIZE:
            raise ValueError("AES-CMAC key must be exactly 16 bytes (32 hex characters)")
        self._cipher = new_block_cipher(bytes(key))
        # генерация подключей: L = E_K(0^128), K1 = 2*L, K2 = 2*K1
        l_value = self._cipher.encrypt(b"\x00" * BLOCK_SIZE)
        self._k1 = _double(l_value)
        self._k2 = _double(self._k1)
        self._state = b"\x00" * BLOCK_SIZE   # текущее значение CBC-MAC
        self._buffer = b""                   # необработанный хвост

    def update(self, data):
        self._buffer += data
        # последний блок (даже полный) нужно оставить: он обрабатывается особо с K1 или K2
        ready = ((len(self._buffer) - 1) // BLOCK_SIZE) * BLOCK_SIZE if self._buffer else 0
        for offset in range(0, ready, BLOCK_SIZE):
            block = self._buffer[offset:offset + BLOCK_SIZE]
            self._state = self._cipher.encrypt(xor_bytes(self._state, block))
        self._buffer = self._buffer[ready:]

    def digest(self):
        """Итоговая метка 16 байт; состояние объекта не меняется."""
        tail = self._buffer
        if len(tail) == BLOCK_SIZE:
            last = xor_bytes(tail, self._k1)            # полный последний блок
        else:
            padded = tail + b"\x80" + b"\x00" * (BLOCK_SIZE - len(tail) - 1)
            last = xor_bytes(padded, self._k2)          # неполный или пустой: дополняем 10...0
        return self._cipher.encrypt(xor_bytes(self._state, last))

    def hexdigest(self):
        return self.digest().hex()
