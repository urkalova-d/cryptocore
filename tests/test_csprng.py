"""Тесты для модуля src/csprng.py.

Покрывает:
- TEST-2: уникальность 1000 сгенерированных 16-байтовых ключей.
- TEST-4: грубая проверка распределения бит (Hamming weight ~50%).
- базовые проверки типа/длины результата и граничного случая num_bytes=0.

Полноценный статистический аудит (TEST-3, набор NIST STS из 15 тестов)
инструментом из этого репозитория не является — ниже есть только функция
подготовки тестовых данных для него, запускаемая отдельно вручную
(см. README.md/раздел про NIST STS).
"""
from src.csprng import generate_random_bytes


def test_generate_random_bytes_length_and_type():
    """Результат должен быть bytes запрошенной длины."""
    data = generate_random_bytes(32)
    assert isinstance(data, bytes)
    assert len(data) == 32


def test_generate_random_bytes_zero_length():
    """Граничный случай: 0 байт — валидный запрос, должен вернуть b''."""
    assert generate_random_bytes(0) == b""


def test_generate_random_bytes_negative_length_raises():
    """Отрицательная длина — программная ошибка вызывающего кода, а не ОС."""
    try:
        generate_random_bytes(-1)
        assert False, "Ожидался ValueError для отрицательного num_bytes"
    except ValueError:
        pass


def test_key_uniqueness():
    """TEST-2: 1000 сгенерированных 16-байтовых ключей не должны повторяться.

    Вероятность совпадения двух значений из 2^128 возможных при 1000
    попытках астрономически мала (это парадокс дней рождения, но для
    пространства в 2^128, а не 365) — любое совпадение means серьёзный
    дефект генератора, а не "не повезло".
    """
    num_keys = 1000
    keys = {generate_random_bytes(16).hex() for _ in range(num_keys)}
    assert len(keys) == num_keys, "Обнаружен повторяющийся ключ — критический дефект CSPRNG"


def test_basic_distribution_hamming_weight():
    """TEST-4: в среднем около половины бит в случайных байтах должны быть равны 1.

    Это не строгий статистический тест (его роль выполняет NIST STS,
    см. README.md), а быстрая дымовая проверка: если генератор сломан и,
    например, всегда возвращает нули или все биты в основном 0 или 1,
    это обнаружится сразу же без долгого прогона внешнего инструмента.
    """
    num_keys = 500
    total_bits = num_keys * 16 * 8
    set_bits = 0

    for _ in range(num_keys):
        key = generate_random_bytes(16)
        set_bits += sum(bin(byte).count("1") for byte in key)

    fraction = set_bits / total_bits
    assert 0.45 <= fraction <= 0.55, (
        f"Доля единичных бит {fraction:.3f} заметно отличается от ожидаемых ~0.5 — "
        f"возможна проблема с источником случайности"
    )


def prepare_nist_test_data(path="nist_test_data.bin", total_size=10_000_000):
    """Вспомогательная функция (не автотест) для подготовки данных к TEST-3.

    Генерирует файл случайных байт нужного размера для прогона через
    внешний NIST Statistical Test Suite. Запуск вручную:

        python -c "from tests.test_csprng import prepare_nist_test_data; prepare_nist_test_data()"
    """
    with open(path, "wb") as f:
        bytes_written = 0
        while bytes_written < total_size:
            chunk_size = min(4096, total_size - bytes_written)
            f.write(generate_random_bytes(chunk_size))
            bytes_written += chunk_size
    print(f"Сгенерировано {bytes_written} байт для NIST STS в '{path}'")


if __name__ == "__main__":
    test_generate_random_bytes_length_and_type()
    test_generate_random_bytes_zero_length()
    test_generate_random_bytes_negative_length_raises()
    test_key_uniqueness()
    test_basic_distribution_hamming_weight()
    print("Все тесты CSPRNG прошли успешно.")
