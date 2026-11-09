"""Encrypt-then-MAC: шифрование любым блочным режимом + HMAC-SHA-256 (AEAD-1).

Схема:
    K_e, K_m = KDF(мастер-ключ)             # разделение ключей
    C = E(K_e, IV, P)                       # шифруем
    T = HMAC(K_m, IV || C || AAD || len(AAD))   # метка считается по шифротексту
    выход = C || T

Относительно формулы из ТЗ (T = MAC(K_m, C || AAD)) в метку добавлены IV и длина
AAD. Без IV злоумышленник мог бы подменить IV (в CTR это даёт предсказуемую
правку открытого текста), а метка осталась бы верной; без длины границу между C
и AAD можно было бы сдвинуть. Проверка метки идёт ДО расшифрования.
"""
import secrets

from src.aead.errors import AuthenticationError
from src.mac.hmac import HMAC
from src.modes.cbc import encrypt_cbc, decrypt_cbc
from src.modes.cfb import encrypt_cfb, decrypt_cfb
from src.modes.ctr import encrypt_ctr, decrypt_ctr
from src.modes.ofb import encrypt_ofb, decrypt_ofb

IV_SIZE = 16     # размер IV для всех поддерживаемых режимов
TAG_SIZE = 32    # длина HMAC-SHA-256

# имя режима -> (шифрование, расшифрование); у всех сигнатура (ключ, iv, данные)
CIPHER_MODES = {
    "ctr": (encrypt_ctr, decrypt_ctr),
    "cbc": (encrypt_cbc, decrypt_cbc),
    "cfb": (encrypt_cfb, decrypt_cfb),
    "ofb": (encrypt_ofb, decrypt_ofb),
}

_ENC_LABEL = b"cryptocore-etm-encryption-key"
_MAC_LABEL = b"cryptocore-etm-mac-key"


def derive_keys(master_key: bytes):
    """Разделение ключей: K_e (16 байт для AES) и K_m (32 байта для HMAC).

    Каждый ключ - HMAC-SHA-256 от мастер-ключа с разной меткой, поэтому знание
    одного из них не помогает получить другой или мастер-ключ.
    """
    def kdf(label):
        mac = HMAC(master_key, "sha256")
        mac.update(label)
        return mac.digest()

    return kdf(_ENC_LABEL)[:16], kdf(_MAC_LABEL)


def _compute_tag(mac_key: bytes, iv: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    mac = HMAC(mac_key, "sha256")
    mac.update(iv)
    mac.update(ciphertext)
    mac.update(aad)
    mac.update(len(aad).to_bytes(8, "big"))
    return mac.digest()


def _get_mode(cipher_mode: str):
    try:
        return CIPHER_MODES[cipher_mode]
    except KeyError:
        raise ValueError(f"Encrypt-then-MAC does not support mode '{cipher_mode}'")


def etm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"",
                cipher_mode: str = "ctr") -> bytes:
    """Вернуть шифротекст || метка (IV в вывод не входит, его добавляет вызывающий код)."""
    if len(iv) != IV_SIZE:
        raise ValueError(f"IV must be {IV_SIZE} bytes")
    encrypt, _ = _get_mode(cipher_mode)
    enc_key, mac_key = derive_keys(key)
    ciphertext = encrypt(enc_key, iv, plaintext)
    return ciphertext + _compute_tag(mac_key, iv, ciphertext, aad)


def etm_decrypt(key: bytes, iv: bytes, data: bytes, aad: bytes = b"",
                cipher_mode: str = "ctr") -> bytes:
    """Принять шифротекст || метка; при неверной метке бросить AuthenticationError."""
    if len(iv) != IV_SIZE:
        raise ValueError(f"IV must be {IV_SIZE} bytes")
    if len(data) < TAG_SIZE:
        raise ValueError(
            f"Encrypt-then-MAC input is too short: need at least {TAG_SIZE} bytes "
            f"for the tag, got {len(data)}"
        )
    _, decrypt = _get_mode(cipher_mode)
    enc_key, mac_key = derive_keys(key)
    ciphertext, tag = data[:-TAG_SIZE], data[-TAG_SIZE:]
    if not secrets.compare_digest(_compute_tag(mac_key, iv, ciphertext, aad), tag):
        raise AuthenticationError("Encrypt-then-MAC tag mismatch")
    return decrypt(enc_key, iv, ciphertext)
