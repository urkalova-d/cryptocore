""" AES-128 ECB с PKCS#7"""
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes) -> bytes:
    """дополнение data до кратного блок сайз с помощью PKCS#7"""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    """проверка и снятие дополнения PKCS#7 с data"""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Некорректная длина дополненных данных")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Некорректное дополнение PKCS#7")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Некорректное дополнение PKCS#7")

    return data[:-pad_len]


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """зашифровка plaintext по AES-128-ECB с дополнением PKCS#7"""
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext)

    ciphertext = bytearray()
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        ciphertext += cipher.encrypt(block)

    return bytes(ciphertext)


def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """расшифровка ciphertext по AES-128-ECB и снять дополнение PKCS#7"""
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Длина шифротекста не кратна размеру блока")

    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = bytearray()
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        plaintext += cipher.decrypt(block)

    return pkcs7_unpad(bytes(plaintext))