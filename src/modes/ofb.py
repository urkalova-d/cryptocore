"""Режим OFB """
from .common import BLOCK_SIZE, xor_bytes, new_block_cipher


def _ofb_transform(key: bytes, iv: bytes, data: bytes) -> bytes:
    """ шифрование и расшифрование - одна и та же операция"""
    cipher = new_block_cipher(key)

    result = bytearray()
    feedback = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        chunk = data[offset:offset + BLOCK_SIZE]
        feedback = cipher.encrypt(feedback)  # keystream-блок, не зависит от chunk
        result += xor_bytes(chunk, feedback[:len(chunk)])

    return bytes(result)


def encrypt_ofb(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return _ofb_transform(key, iv, plaintext)


def decrypt_ofb(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return _ofb_transform(key, iv, ciphertext)
