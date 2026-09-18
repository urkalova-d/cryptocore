"""aes-128 ECB mode с PKCS#7 """
from .common import BLOCK_SIZE, pkcs7_pad, pkcs7_unpad, new_block_cipher


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """зашифровать плейнтекст в режиме AES-128-ECB с PKCS#7"""
    cipher = new_block_cipher(key)
    padded = pkcs7_pad(plaintext)

    ciphertext = bytearray()
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        ciphertext += cipher.encrypt(block)

    return bytes(ciphertext)


def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """расшифровать шифртекст, зашифрованный AES-128-ECB, и снять padding"""
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length is not a multiple of the block size")

    cipher = new_block_cipher(key)

    plaintext = bytearray()
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        plaintext += cipher.decrypt(block)

    return pkcs7_unpad(bytes(plaintext))
