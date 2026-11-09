"""Режим GCM (Galois/Counter Mode) по NIST SP 800-38D, написанный с нуля.

Состав:
  * умножение в поле GF(2^128) по неприводимому многочлену x^128 + x^7 + x^2 + x + 1
    (медленная эталонная версия gf_mult и быстрая табличная _mult_h);
  * потоковый GHASH: AAD можно подавать порциями, не загружая целиком в память;
  * CTR-шифрование со счётчиком inc32 (увеличиваются только последние 32 бита);
  * класс GCM по структуре из ТЗ и функции gcm_encrypt / gcm_decrypt в стиле
    остальных режимов проекта (ключ, nonce, данные).

Формат шифротекста: nonce (12 байт) || шифротекст || тег (16 байт).
"""
import secrets

from src.aead.errors import AuthenticationError
from src.csprng import generate_random_bytes
from .common import BLOCK_SIZE, new_block_cipher

NONCE_SIZE = 12          # рекомендованная длина nonce в GCM
TAG_SIZE = 16            # длина тега аутентификации
_CHUNK_BLOCKS = 4096     # сколько блоков счётчика шифруется за один вызов AES
_MASK32 = 0xFFFFFFFF

# В GCM старший бит байта - коэффициент при младшей степени x ("отражённое"
# представление), поэтому умножение на x - это сдвиг ВПРАВО, а константа
# редукции x^7 + x^2 + x + 1 выглядит как 0xE1 в старшем байте.
_R = 0xE1 << 120


def _mulx(v: int) -> int:
    """Умножение элемента поля на x: сдвиг вправо и редукция выпавшего бита."""
    return (v >> 1) ^ _R if v & 1 else v >> 1


def gf_mult(x: int, y: int) -> int:
    """Эталонное умножение в GF(2^128) бит за битом (как в примере из ТЗ).

    Медленное: 128 итераций на одно умножение. В режиме не используется,
    нужно для проверки быстрой версии в тестах.
    """
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = _mulx(v)
    return z


def _build_tables(h: int):
    """Таблица умножения на H для каждого байта: table[n] = n * H.

    Байт n - это 8 коэффициентов при x^0..x^7 (старший бит - x^0), поэтому
    n * H = XOR степеней x^i * H по установленным битам. Таблица строится один
    раз на ключ (256 значений), затем одно умножение - это 16 обращений к ней.
    """
    powers = [h]
    for _ in range(7):
        powers.append(_mulx(powers[-1]))          # powers[i] = x^i * H
    table = [0] * 256
    for n in range(256):
        v = 0
        for i in range(8):
            if (n >> (7 - i)) & 1:
                v ^= powers[i]
        table[n] = v
    return table


def _build_reduction():
    """reduce8[r] - вклад младшего байта r при умножении на x^8 (сдвиг на 8 бит вправо)."""
    reduce8 = [0] * 256
    for r in range(256):
        v = r
        for _ in range(8):
            v = _mulx(v)
        reduce8[r] = v
    return reduce8


_REDUCE8 = _build_reduction()


def _mult_h(table, x: int) -> int:
    """x * H в GF(2^128) через таблицу (схема Хорнера по байтам x).

    Идём от младшего байта x к старшему: Z = Z * x^8 + table[байт]. Умножение
    на x^8 - это сдвиг вправо на 8 бит плюс поправка _REDUCE8 за выпавший байт.
    """
    z = 0
    for shift in range(0, 128, 8):
        z = (z >> 8) ^ _REDUCE8[z & 0xFF] ^ table[(x >> shift) & 0xFF]
    return z


class _GHash:
    """Потоковый GHASH: Y = (Y xor блок) * H для каждого 16-байтового блока."""

    def __init__(self, table):
        self._table = table
        self._y = 0
        self._buf = b""      # неполный хвост, ждущий следующей порции
        self.length = 0      # сколько байт подано через update (без добавленных нулей)

    def update(self, data):
        self.length += len(data)
        self._absorb(data)

    def _absorb(self, data):
        if self._buf:
            data = self._buf + data
        full = len(data) - len(data) % BLOCK_SIZE
        y, table = self._y, self._table
        for off in range(0, full, BLOCK_SIZE):
            y = _mult_h(table, y ^ int.from_bytes(data[off:off + BLOCK_SIZE], "big"))
        self._y = y
        self._buf = bytes(data[full:])

    def pad(self):
        """Дополнить текущую часть (AAD или шифротекст) нулями до границы блока."""
        if self._buf:
            self._absorb(b"\x00" * (BLOCK_SIZE - len(self._buf)))

    def finish(self, aad_len: int, ct_len: int) -> int:
        """Добавить блок длин (в битах, по 64 бита) и вернуть результат GHASH."""
        self._absorb(((aad_len * 8) << 64 | (ct_len * 8)).to_bytes(BLOCK_SIZE, "big"))
        return self._y


def _feed(ghash, data):
    """Подать в GHASH байты либо любой итератор порций байт (для AAD больше памяти)."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        ghash.update(bytes(data))
    else:
        for chunk in data:
            ghash.update(bytes(chunk))


class GCM:
    """AES-GCM. Объект привязан к ключу; nonce по умолчанию генерируется случайно."""

    def __init__(self, key, nonce=None):
        if nonce is None:
            nonce = generate_random_bytes(NONCE_SIZE)
        if len(nonce) == 0:
            raise ValueError("GCM nonce must not be empty")
        self.nonce = bytes(nonce)
        self._cipher = new_block_cipher(bytes(key))
        # H = E_K(0^128) - ключ хэширования; таблица считается один раз
        h = int.from_bytes(self._cipher.encrypt(b"\x00" * BLOCK_SIZE), "big")
        self._table = _build_tables(h)

    def _j0(self, nonce: bytes) -> int:
        """Начальный блок счётчика J0 (раздел 7.1 стандарта)."""
        if len(nonce) == NONCE_SIZE:
            return int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
        # nonce другой длины сворачивается через GHASH
        gh = _GHash(self._table)
        gh.update(nonce)
        gh.pad()
        return gh.finish(0, len(nonce))

    def _ghash(self, aad, ciphertext: bytes) -> int:
        """GHASH(AAD, шифротекст): оба поля дополняются нулями, в конце блок длин."""
        gh = _GHash(self._table)
        _feed(gh, aad)
        aad_len = gh.length
        gh.pad()
        gh.length = 0
        gh.update(ciphertext)
        ct_len = gh.length
        gh.pad()
        return gh.finish(aad_len, ct_len)

    def _ctr_xor(self, j0: int, data: bytes) -> bytes:
        """Шифрование/расшифрование CTR: счётчики J0+1, J0+2, ... (inc32).

        Блоки счётчика шифруются пачками (один вызов AES на много блоков),
        это заметно быстрее, чем по одному.
        """
        high = j0 & ~_MASK32
        counter = j0 & _MASK32
        out = []
        step = _CHUNK_BLOCKS * BLOCK_SIZE
        for pos in range(0, len(data), step):
            chunk = data[pos:pos + step]
            n_blocks = (len(chunk) + BLOCK_SIZE - 1) // BLOCK_SIZE
            counters = b"".join(
                (high | ((counter + 1 + i) & _MASK32)).to_bytes(BLOCK_SIZE, "big")
                for i in range(n_blocks)
            )
            keystream = self._cipher.encrypt(counters)
            counter = (counter + n_blocks) & _MASK32
            n = len(chunk)
            out.append((int.from_bytes(chunk, "big")
                        ^ int.from_bytes(keystream[:n], "big")).to_bytes(n, "big"))
        return b"".join(out)

    def _tag(self, j0: int, aad, ciphertext: bytes) -> bytes:
        s = self._ghash(aad, ciphertext)
        ek_j0 = int.from_bytes(self._cipher.encrypt(j0.to_bytes(BLOCK_SIZE, "big")), "big")
        return (ek_j0 ^ s).to_bytes(TAG_SIZE, "big")

    def seal(self, nonce: bytes, plaintext: bytes, aad=b""):
        """Вернуть (шифротекст, тег) для заданного nonce."""
        j0 = self._j0(nonce)
        ciphertext = self._ctr_xor(j0, plaintext)
        return ciphertext, self._tag(j0, aad, ciphertext)

    def unseal(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad=b"") -> bytes:
        """Проверить тег и только потом расшифровать (AEAD-6)."""
        j0 = self._j0(nonce)
        # сравнение за постоянное время, чтобы тег нельзя было подбирать по времени ответа
        if not secrets.compare_digest(self._tag(j0, aad, ciphertext), tag):
            raise AuthenticationError("GCM tag mismatch")
        return self._ctr_xor(j0, ciphertext)

    def encrypt(self, plaintext: bytes, aad=b"") -> bytes:
        """Вернуть nonce || шифротекст || тег."""
        ciphertext, tag = self.seal(self.nonce, plaintext, aad)
        return self.nonce + ciphertext + tag

    def decrypt(self, data: bytes, aad=b"") -> bytes:
        """Разобрать nonce || шифротекст || тег, проверить тег, вернуть открытый текст."""
        nonce_len = len(self.nonce)
        if len(data) < nonce_len + TAG_SIZE:
            raise ValueError(
                f"GCM input is too short: need at least {nonce_len + TAG_SIZE} bytes "
                f"(nonce + tag), got {len(data)}"
            )
        nonce = data[:nonce_len]
        ciphertext = data[nonce_len:-TAG_SIZE]
        tag = data[-TAG_SIZE:]
        return self.unseal(nonce, ciphertext, tag, aad)


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad=b"") -> bytes:
    """Шифротекст || тег (nonce в вывод не входит - его добавляет вызывающий код)."""
    ciphertext, tag = GCM(key, nonce).seal(nonce, plaintext, aad)
    return ciphertext + tag


def gcm_decrypt(key: bytes, nonce: bytes, data: bytes, aad=b"") -> bytes:
    """Принимает шифротекст || тег; при неверном теге бросает AuthenticationError."""
    if len(data) < TAG_SIZE:
        raise ValueError(
            f"GCM input is too short: need at least {TAG_SIZE} bytes for the tag, got {len(data)}"
        )
    return GCM(key, nonce).unseal(nonce, data[:-TAG_SIZE], data[-TAG_SIZE:], aad)
