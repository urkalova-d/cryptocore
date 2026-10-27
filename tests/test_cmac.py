"""AES-CMAC: тестовые векторы NIST SP 800-38B (TEST-8)."""
import unittest

from src.mac.cmac import CMAC

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
MESSAGE = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
# длина сообщения -> ожидаемая метка (пример AES-128 из приложения D документа)
VECTORS = {
    0: "bb1d6929e95937287fa37d129b756746",
    16: "070a16b46b4d4144f79bdd9dd04a287c",
    40: "dfa66747de9ae63030ca32611497c827",
    64: "51f0bebf7e3b9d92fc49741779363cfe",
}


class TestCmac(unittest.TestCase):
    def test_subkeys(self):
        mac = CMAC(KEY)
        self.assertEqual(mac._k1.hex(), "fbeed618357133667c85e08f7236a8de")
        self.assertEqual(mac._k2.hex(), "f7ddac306ae266ccf90bc11ee46d513b")

    def test_vectors(self):
        for length, expected in VECTORS.items():
            with self.subTest(length=length):
                mac = CMAC(KEY)
                mac.update(MESSAGE[:length])
                self.assertEqual(mac.hexdigest(), expected)

    def test_streaming(self):
        for length, expected in VECTORS.items():
            mac = CMAC(KEY)
            for i in range(length):                # по одному байту
                mac.update(MESSAGE[i:i + 1])
            self.assertEqual(mac.hexdigest(), expected)

    def test_bad_key(self):
        with self.assertRaises(ValueError):
            CMAC(b"short")


if __name__ == "__main__":
    unittest.main()
