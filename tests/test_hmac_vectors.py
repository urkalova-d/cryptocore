"""HMAC: тестовые векторы RFC 4231 (TEST-1), размеры ключей (TEST-5), сверка с hashlib."""
import hashlib
import hmac as std_hmac
import os
import unittest

from src.mac.hmac import HMAC

# (ключ, данные, ожидаемый HMAC-SHA-256) - тестовые случаи 1-4, 6, 7 из RFC 4231
RFC_4231 = [
    ("0b" * 20, b"Hi There".hex(),
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe".hex(), b"what do ya want for nothing?".hex(),
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    ("aa" * 20, "dd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    (bytes(range(1, 26)).hex(), "cd" * 50,
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    ("aa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First".hex(),
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    ("aa" * 131,
     (b"This is a test using a larger than block-size key and a larger than "
      b"block-size data. The key needs to be hashed before being used by the "
      b"HMAC algorithm.").hex(),
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
]


class TestRfc4231(unittest.TestCase):
    def test_vectors(self):
        for i, (key, data, expected) in enumerate(RFC_4231, 1):
            with self.subTest(case=i):
                self.assertEqual(HMAC(bytes.fromhex(key), "sha256").compute(bytes.fromhex(data)),
                                 expected)

    def test_streaming_equals_compute(self):
        key, data, expected = bytes.fromhex(RFC_4231[3][0]), bytes.fromhex(RFC_4231[3][1]), RFC_4231[3][2]
        mac = HMAC(key)
        for i in range(0, len(data), 7):          # подаём кусками по 7 байт
            mac.update(data[i:i + 7])
        self.assertEqual(mac.hexdigest(), expected)
        self.assertEqual(mac.hexdigest(), expected)   # повторный вызов не ломает состояние


class TestKeySizes(unittest.TestCase):
    """TEST-5: ключи короче блока, равные блоку и длиннее; плюс пустой ключ и пустое сообщение (TEST-6)."""

    def test_against_hashlib(self):
        for algo, std in (("sha256", "sha256"), ("sha3-256", "sha3_256")):
            for key_len in (0, 1, 16, 63, 64, 65, 100, 135, 136, 137, 300):
                for msg_len in (0, 1, 55, 64, 1000):
                    key, msg = os.urandom(key_len), os.urandom(msg_len)
                    with self.subTest(algo=algo, key=key_len, msg=msg_len):
                        self.assertEqual(HMAC(key, algo).compute(msg),
                                         std_hmac.new(key, msg, std).hexdigest())

    def test_unknown_hash(self):
        with self.assertRaises(ValueError):
            HMAC(b"k", "md5")

    def test_long_key_equals_hashed_key(self):
        long_key = os.urandom(100)
        self.assertEqual(HMAC(long_key).compute(b"m"),
                         HMAC(hashlib.sha256(long_key).digest()).compute(b"m"))


if __name__ == "__main__":
    unittest.main()
