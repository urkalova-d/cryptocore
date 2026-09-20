"""Режим CTR"""
from .common import BLOCK_SIZE, xor_bytes, new_block_cipher


def _increment_counter(counter_int: int) -> int:
    """увеличение счётчика на 1 по модулю 2^128(переполнение блока)"""
    return (counter_int + 1) % (2 ** (BLOCK_SIZE * 8))


def _ctr_transform(key: bytes, iv: bytes, data: bytes) -> bytes:
    """ шифрование и расшифрование - одна и та же операция"""
    cipher = new_block_cipher(key)

    result = bytearray()
    counter = int.from_bytes(iv, byteorder="big")  # вектор инициализации задаёт стартовое значение счётчика
    for offset in range(0, len(data), BLOCK_SIZE):
        chunk = data[offset:offset + BLOCK_SIZE]
        counter_block = counter.to_bytes(BLOCK_SIZE, byteorder="big")
        keystream = cipher.encrypt(counter_block)
        result += xor_bytes(chunk, keystream[:len(chunk)])
        counter = _increment_counter(counter)  #свой счётчик для каждого следующего блока

    return bytes(result)


def encrypt_ctr(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return _ctr_transform(key, iv, plaintext)


def decrypt_ctr(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return _ctr_transform(key, iv, ciphertext)
