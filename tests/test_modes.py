""" тесты для всех режимов"""
import os
import subprocess
import sys
import tempfile

KEY = "000102030405060708090a0b0c0d0e0f"
MODES = ["ecb", "cbc", "cfb", "ofb", "ctr"]
LENGTHS = [0, 1, 15, 16, 17, 31, 32, 100]


def run_cryptocore(*args):
    return subprocess.run(
        [sys.executable, "-m", "src.main", *args],
        capture_output=True, text=True,
    )


def _roundtrip(mode: str, length: int, tmp: str):
    original = os.path.join(tmp, f"plain_{mode}_{length}.bin")
    encrypted = os.path.join(tmp, f"cipher_{mode}_{length}.bin")
    decrypted = os.path.join(tmp, f"decrypted_{mode}_{length}.bin")

    with open(original, "wb") as f:
        f.write(os.urandom(length))

    enc = run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--encrypt",
        "--key", KEY, "--input", original, "--output", encrypted,
    )
    assert enc.returncode == 0, f"[{mode}/{length}] encrypt failed: {enc.stderr}"

    dec = run_cryptocore(
        "--algorithm", "aes", "--mode", mode, "--decrypt",
        "--key", KEY, "--input", encrypted, "--output", decrypted,
    )
    assert dec.returncode == 0, f"[{mode}/{length}] decrypt failed: {dec.stderr}"

    with open(original, "rb") as f1, open(decrypted, "rb") as f2:
        assert f1.read() == f2.read(), f"[{mode}/{length}] mismatch after round-trip"


def test_roundtrip_all_modes_all_lengths():
    with tempfile.TemporaryDirectory() as tmp:
        for mode in MODES:
            for length in LENGTHS:
                _roundtrip(mode, length, tmp)


def test_explicit_iv_roundtrip():
    """расшифровка с явно переданным --iv (не из тела файла) должна тоже работать"""
    with tempfile.TemporaryDirectory() as tmp:
        original = os.path.join(tmp, "plain.bin")
        encrypted = os.path.join(tmp, "cipher.bin")
        body_only = os.path.join(tmp, "cipher_body.bin")
        decrypted = os.path.join(tmp, "decrypted.bin")

        with open(original, "wb") as f:
            f.write(b"explicit IV roundtrip test payload")

        enc = run_cryptocore(
            "--algorithm", "aes", "--mode", "cbc", "--encrypt",
            "--key", KEY, "--input", original, "--output", encrypted,
        )
        assert enc.returncode == 0, enc.stderr

        with open(encrypted, "rb") as f:
            full = f.read()
        iv_hex = full[:16].hex()
        with open(body_only, "wb") as f:
            f.write(full[16:])

        dec = run_cryptocore(
            "--algorithm", "aes", "--mode", "cbc", "--decrypt",
            "--key", KEY, "--iv", iv_hex, "--input", body_only, "--output", decrypted,
        )
        assert dec.returncode == 0, dec.stderr

        with open(original, "rb") as f1, open(decrypted, "rb") as f2:
            assert f1.read() == f2.read()


def test_short_file_raises_error():
    """Файл короче 16 байт при decrypt без --iv должен давать ошибку"""
    with tempfile.TemporaryDirectory() as tmp:
        short_file = os.path.join(tmp, "short.bin")
        with open(short_file, "wb") as f:
            f.write(b"\x01\x02\x03")

        result = run_cryptocore(
            "--algorithm", "aes", "--mode", "cbc", "--decrypt",
            "--key", KEY, "--input", short_file, "--output", os.path.join(tmp, "out.bin"),
        )
        assert result.returncode != 0
        assert "IV" in result.stderr


if __name__ == "__main__":
    test_roundtrip_all_modes_all_lengths()
    test_explicit_iv_roundtrip()
    test_short_file_raises_error()
    print("Все тесты прошли успешно.")
