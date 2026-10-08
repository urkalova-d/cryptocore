"""SHA3-256 с нуля по спецификации NIST FIPS 202 (конструкция "губка" Keccak)"""

MASK64 = 0xFFFFFFFFFFFFFFFF  # маска для 64-битной арифметики

RATE_BYTES = 136  # rate = 1088 бит для SHA3-256

# Константы раундов Keccak-f[1600] (iota), по одной на каждый из 24 раундов
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Смещения циклических сдвигов (rho) для каждой позиции [x][y] решётки
ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol64(x: int, n: int) -> int:
    """Циклический сдвиг 64-битного слова влево на n бит."""
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _keccak_f(state):
    """Перестановка Keccak-f[1600]: 24 раунда над решёткой state[x][y]."""
    for rnd in range(24):
        # theta: каждый столбец "подмешивается" в соседние столбцы
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]

        # rho + pi: сдвиг каждого слова на своё смещение и перестановка позиций
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol64(state[x][y], ROTATION_OFFSETS[x][y])

        # chi: единственный нелинейный шаг (работает по строкам)
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & MASK64) & b[(x + 2) % 5][y])

        # iota: добавляем константу раунда, чтобы раунды отличались друг от друга
        state[0][0] ^= ROUND_CONSTANTS[rnd]


class SHA3_256:
    def __init__(self):
        # решётка 5x5 из 64-битных слов, изначально нули
        self._state = [[0] * 5 for _ in range(5)]
        self._buffer = b""   # хвост, не набравший полный блок rate (< 136 байт)

    def _absorb_block(self, state, block):
        """XOR блока (ровно rate байт) в состояние и перестановка Keccak-f"""
        # блок читается как 17 слов по 8 байт в порядке little-endian;
        # слово i лежит в решётке на позиции x = i % 5, y = i // 5
        for i in range(RATE_BYTES // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)

    def update(self, message: bytes):
        """Подать очередную порцию данных (можно вызывать многократно)"""
        self._buffer += message
        full = len(self._buffer) - (len(self._buffer) % RATE_BYTES)
        for offset in range(0, full, RATE_BYTES):
            self._absorb_block(self._state, self._buffer[offset:offset + RATE_BYTES])
        self._buffer = self._buffer[full:]

    def padding(self, tail: bytes) -> bytes:
        """ суффикс '01' + pad10*1, результат кратен rate"""
        pad_len = RATE_BYTES - (len(tail) % RATE_BYTES)
        if pad_len == 1:
            return tail + b"\x86"
        return tail + b"\x06" + b"\x00" * (pad_len - 2) + b"\x80"

    def digest(self) -> bytes:
        """Итоговый хэш (32 байта). Состояние объекта не меняется."""
        # работаем с копией состояния, чтобы digest() можно было звать повторно
        state = [row[:] for row in self._state]
        padded = self.padding(self._buffer)
        for offset in range(0, len(padded), RATE_BYTES):
            self._absorb_block(state, padded[offset:offset + RATE_BYTES])

        # squeeze: 32 байта хэша умещаются в первый блок rate (136 байт),
        # поэтому повторная перестановка не нужна
        out = b""
        for i in range(4):  # 4 слова по 8 байт = 32 байта
            out += state[i % 5][i // 5].to_bytes(8, "little")
        return out

    def hexdigest(self) -> str:
        """Итоговый хэш строкой из строчных hex-символов (HASH-6)."""
        return self.digest().hex()

    def hash(self, message: bytes) -> str:
        """Удобная обёртка: хэш всего сообщения целиком (сбрасывает состояние)."""
        self.__init__()
        self.update(message)
        return self.hexdigest()
