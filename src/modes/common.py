"""вспомогательные функции для режимов работы AES"""
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # размер блока


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """побайтовый ксор, длины a и b должны совпадать(если b длиннее,лишнее отбросится)"""
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes) -> bytes:
    """Дополнить data до кратности BLOCK_SIZE по правилам PKCS#7"""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    """Проверить и убрать PKCS#7 padding"""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded data length")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid PKCS#7 padding")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")

    return data[:-pad_len]


def new_block_cipher(key: bytes):
    """Вернуть объект, чей encrypt()/decrypt() шифрует/дешифрует ровно один блок"""
    return AES.new(key, AES.MODE_ECB)
