"""SHA-256 с нуля по спецификации NIST FIPS 180-4.

Схема работы (конструкция Меркла-Дамгарда):
  1. Сообщение дополняется (padding) до длины, кратной 512 бит (64 байта).
  2. Дополненное сообщение режется на блоки по 64 байта.
  3. Каждый блок "перемешивается" с текущим внутренним состоянием
     (8 слов по 32 бита) функцией сжатия — 64 раунда.
  4. Итоговое состояние после последнего блока и есть хэш (256 бит).

Класс устроен потоково: данные можно подавать порциями через update(),
внутри хранится только состояние (8 слов), хвост неполного блока (<64 байт)
и счётчик длины — поэтому расход памяти не зависит от размера файла.
"""

MASK32 = 0xFFFFFFFF  # маска для имитации 32-битной арифметики в Python

# Начальные значения хэша: первые 32 бита дробных частей
# квадратных корней первых 8 простых чисел (2, 3, 5, 7, 11, 13, 17, 19)
INITIAL_H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# Константы раундов: первые 32 бита дробных частей
# кубических корней первых 64 простых чисел
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

BLOCK_SIZE = 64  # размер блока SHA-256 в байтах (512 бит)


def _rotr(x: int, n: int) -> int:
    """Циклический сдвиг 32-битного слова вправо на n бит."""
    return ((x >> n) | (x << (32 - n))) & MASK32


class SHA256:
    def __init__(self):
        self._h = list(INITIAL_H)   # текущее внутреннее состояние (8 слов)
        self._buffer = b""          # непрошедший обработку хвост (< 64 байт)
        self._length = 0            # общее число обработанных байт сообщения

    @staticmethod
    def _compress(h, block):
        """Функция сжатия: смешивает один 64-байтовый блок с состоянием h.

        Возвращает НОВЫЙ список из 8 слов (исходный h не изменяется) —
        это позволяет digest() вычислять итог, не портя состояние объекта.
        """
        # расписание сообщения: 16 слов блока (big-endian) расширяем до 64
        w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for t in range(16, 64):
            s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
            s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & MASK32)

        a, b, c, d, e, f, g, hh = h

        for t in range(64):
            big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & MASK32 & g)          # "выбор": e решает, брать f или g
            temp1 = (hh + big_s1 + ch + K[t] + w[t]) & MASK32
            big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)          # "большинство" из трёх бит
            temp2 = (big_s0 + maj) & MASK32

            hh = g
            g = f
            f = e
            e = (d + temp1) & MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK32

        # прибавляем результат раундов к исходному состоянию (по модулю 2^32)
        return [(x + y) & MASK32 for x, y in zip(h, [a, b, c, d, e, f, g, hh])]

    def update(self, message: bytes):
        """Подать очередную порцию данных (можно вызывать многократно)."""
        self._length += len(message)
        self._buffer += message

        # обрабатываем все полные 64-байтовые блоки, хвост оставляем в буфере
        full = len(self._buffer) - (len(self._buffer) % BLOCK_SIZE)
        for offset in range(0, full, BLOCK_SIZE):
            self._h = self._compress(self._h, self._buffer[offset:offset + BLOCK_SIZE])
        self._buffer = self._buffer[full:]

    def padding(self, tail: bytes, total_length: int) -> bytes:
        """Padding по FIPS 180-4: бит '1', нули, затем 64-битная длина в битах.

        tail — необработанный хвост сообщения, total_length — полная длина
        исходного сообщения в БАЙТАХ. Результат кратен 64 байтам.
        """
        padded = tail + b"\x80"                      # бит '1' + 7 нулевых бит
        while len(padded) % BLOCK_SIZE != 56:        # оставляем 8 байт под длину
            padded += b"\x00"
        padded += (total_length * 8).to_bytes(8, "big")
        return padded

    def digest(self) -> bytes:
        """Итоговый хэш (32 байта). Состояние объекта не меняется."""
        h = list(self._h)
        padded = self.padding(self._buffer, self._length)
        for offset in range(0, len(padded), BLOCK_SIZE):
            h = self._compress(h, padded[offset:offset + BLOCK_SIZE])
        return b"".join(word.to_bytes(4, "big") for word in h)

    def hexdigest(self) -> str:
        """Итоговый хэш строкой из строчных hex-символов (HASH-6)."""
        return self.digest().hex()

    def hash(self, message: bytes) -> str:
        """Удобная обёртка: хэш всего сообщения целиком (сбрасывает состояние)."""
        self.__init__()
        self.update(message)
        return self.hexdigest()
