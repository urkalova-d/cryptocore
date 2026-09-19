"""Режим CFB"""
from .common import BLOCK_SIZE, xor_bytes, new_block_cipher

def encrypt_cfb(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = new_block_cipher(key)

    ciphertext = bytearray()
    feedback = iv
    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset:offset + BLOCK_SIZE]
        keystream = cipher.encrypt(feedback)[:len(block)]
        enc_block = xor_bytes(block, keystream)
        ciphertext += enc_block
        feedback = enc_block  # обратная связь = только что полученный шифроблок

    return bytes(ciphertext)

def decrypt_cfb(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = new_block_cipher(key)

    plaintext = bytearray()
    feedback = iv
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        keystream = cipher.encrypt(feedback)[:len(block)]
        dec_block = xor_bytes(block, keystream)
        plaintext += dec_block
        feedback = block  # обратная связь = блок шифротекста(тот же,что у отправителя)

    return bytes(plaintext)
