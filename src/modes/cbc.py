"""Режим CBC """
from .common import BLOCK_SIZE, xor_bytes, pkcs7_pad, pkcs7_unpad, new_block_cipher


def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = new_block_cipher(key)
    padded = pkcs7_pad(plaintext)

    ciphertext = bytearray()
    prev_block = iv #для первого блока "предыдущим шифроблоком" служит вектор инициализации
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        xored = xor_bytes(block, prev_block)
        enc_block = cipher.encrypt(xored)
        ciphertext += enc_block
        prev_block = enc_block #сцепление:следующий блок будет ксориться с этим

    return bytes(ciphertext)


def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length is not a multiple of the block size")

    cipher = new_block_cipher(key)

    plaintext = bytearray()
    prev_block = iv
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        dec_block = cipher.decrypt(block)
        plaintext += xor_bytes(dec_block, prev_block)
        prev_block = block  #для расшифровки берём предыдущий шифрблок,а не расшифрованный

    return pkcs7_unpad(bytes(plaintext))
