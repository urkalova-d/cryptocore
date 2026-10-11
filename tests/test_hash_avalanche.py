"""TEST-5: лавинный эффект — малое изменение входа меняет ~половину бит хэша."""
from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256


def _differing_bits(hex1: str, hex2: str) -> int:
    bin1 = bin(int(hex1, 16))[2:].zfill(256)
    bin2 = bin(int(hex2, 16))[2:].zfill(256)
    return sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))


def test_avalanche_effect():
    """Замена последнего символа (пример из ТЗ), оба алгоритма."""
    original_data = b"Hello, world!"
    modified_data = b"Hello, world?"
    for algo in (SHA256, SHA3_256):
        diff_count = _differing_bits(algo().hash(original_data), algo().hash(modified_data))
        print(f"{algo.__name__}: изменилось бит {diff_count}/256")
        # ожидаем около 128 бит (50%)
        assert 100 < diff_count < 156, f"{algo.__name__}: лавинный эффект слабый ({diff_count})"


def test_avalanche_single_bit_flip():
    """Переворот ровно одного бита входа, усреднение по всем 8 позициям бита."""
    data = bytearray(b"The quick brown fox jumps over the lazy dog")
    for algo in (SHA256, SHA3_256):
        base = algo().hash(bytes(data))
        total = 0
        for bit in range(8):
            flipped = bytearray(data)
            flipped[0] ^= 1 << bit
            total += _differing_bits(base, algo().hash(bytes(flipped)))
        average = total / 8
        print(f"{algo.__name__}: в среднем изменилось бит {average:.1f}/256")
        assert 110 < average < 146, f"{algo.__name__}: среднее {average}"


if __name__ == "__main__":
    test_avalanche_effect()
    test_avalanche_single_bit_flip()
    print("Тесты лавинного эффекта прошли успешно.")
