""" шифрование расшифрованием должно вернуть исходный файл"""
import os
import subprocess
import sys
import tempfile

KEY = "000102030405060708090a0b0c0d0e0f"


def run_cryptocore(*args):
    return subprocess.run(
        [sys.executable, "-m", "src.main", *args],
        capture_output=True, text=True,
    )


def test_roundtrip_text_file():
    with tempfile.TemporaryDirectory() as tmp:
        original = os.path.join(tmp, "plaintext.txt")
        encrypted = os.path.join(tmp, "ciphertext.bin")
        decrypted = os.path.join(tmp, "decrypted.txt")

        with open(original, "wb") as f:
            f.write(b"Hello, CryptoCore! This is a round-trip test message.")

        enc = run_cryptocore(
            "--algorithm", "aes", "--mode", "ecb", "--encrypt",
            "--key", KEY, "--input", original, "--output", encrypted,
        )
        assert enc.returncode == 0, enc.stderr

        dec = run_cryptocore(
            "--algorithm", "aes", "--mode", "ecb", "--decrypt",
            "--key", KEY, "--input", encrypted, "--output", decrypted,
        )
        assert dec.returncode == 0, dec.stderr

        with open(original, "rb") as f1, open(decrypted, "rb") as f2:
            assert f1.read() == f2.read()


if __name__ == "__main__":
    test_roundtrip_text_file()
    print("Round-trip test passed.")