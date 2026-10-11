"""Тесты хэш-функций и подкоманды dgst.

Покрывает:
- TEST-1: известные ответы (векторы NIST) для SHA-256 и SHA3-256;
- TEST-2: хэш пустого файла;
- TEST-3: совпадение вывода dgst с эталоном (hashlib / системные *sum);
- границы блоков и потоковую обработку (HASH-4, HASH-5);
- CLI-3: dgst не принимает аргументы шифрования;
- IO-3/IO-4: --output и ошибки файлов.
"""
import hashlib
import os
import subprocess
import sys
import tempfile

from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256

# эталонные значения из документов NIST
SHA256_KAT = {
    b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
}
SHA3_256_KAT = {
    b"": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    b"abc": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
}

ALGORITHMS = {
    "sha256": (SHA256, hashlib.sha256),
    "sha3-256": (SHA3_256, hashlib.sha3_256),
}


def run_dgst(*args):
    return subprocess.run(
        [sys.executable, "-m", "src.main", "dgst", *args],
        capture_output=True, text=True,
    )


def test_known_answers():
    """TEST-1: ответы на векторы NIST."""
    for msg, expected in SHA256_KAT.items():
        assert SHA256().hash(msg) == expected, f"SHA-256 неверен для {msg!r}"
    for msg, expected in SHA3_256_KAT.items():
        assert SHA3_256().hash(msg) == expected, f"SHA3-256 неверен для {msg!r}"


def test_million_a():
    """Длинный вектор NIST: миллион символов 'a' (подаём порциями)."""
    h = SHA256()
    for _ in range(1000):
        h.update(b"a" * 1000)
    assert h.hexdigest() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


def test_block_boundaries_against_hashlib():
    """Длины вокруг границ блока (64 для SHA-256, 136 для SHA3-256) и паддинга."""
    for n in list(range(0, 140)) + [191, 192, 200, 271, 272, 273, 1000]:
        data = os.urandom(n)
        for name, (ours, ref) in ALGORITHMS.items():
            assert ours().hash(data) == ref(data).hexdigest(), f"{name}, {n} байт"


def test_chunked_update_equals_single():
    """Результат не зависит от того, как данные порезаны на порции."""
    data = os.urandom(50_000)
    for name, (ours, ref) in ALGORITHMS.items():
        h = ours()
        for i in range(0, len(data), 777):
            h.update(data[i:i + 777])
        assert h.hexdigest() == ref(data).hexdigest(), name


def test_digest_is_lowercase_hex():
    """HASH-6: строчный hex нужной длины."""
    for name, (ours, _) in ALGORITHMS.items():
        value = ours().hash(b"x")
        assert len(value) == 64 and value == value.lower(), name


def test_cli_empty_file():
    """TEST-2: хэш пустого файла через CLI."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "empty.bin")
        open(path, "wb").close()
        r = run_dgst("--algorithm", "sha256", "--input", path)
        assert r.returncode == 0, r.stderr
        assert r.stdout.split()[0] == SHA256_KAT[b""]
        r = run_dgst("--algorithm", "sha3-256", "--input", path)
        assert r.stdout.split()[0] == SHA3_256_KAT[b""]


def test_cli_matches_reference_and_output_format():
    """TEST-3, CLI-4, IO-3: вывод совпадает с эталоном в формате '<хэш>  <путь>'."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "data.bin")
        data = os.urandom(300_001)
        with open(path, "wb") as f:
            f.write(data)

        for name, (_, ref) in ALGORITHMS.items():
            expected_line = f"{ref(data).hexdigest()}  {path}\n"

            r = run_dgst("--algorithm", name, "--input", path)
            assert r.returncode == 0, r.stderr
            assert r.stdout == expected_line, name

            out_file = os.path.join(tmp, f"{name}.txt")
            r = run_dgst("--algorithm", name, "--input", path, "--output", out_file)
            assert r.returncode == 0, r.stderr
            assert r.stdout == ""
            with open(out_file, "r", encoding="utf-8") as f:
                assert f.read() == expected_line, name


def test_cli_rejects_encryption_arguments():
    """CLI-3: --key/--mode/--encrypt/--decrypt/--iv для dgst недопустимы."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "a.bin")
        with open(path, "wb") as f:
            f.write(b"a")
        for extra in (["--key", "00"], ["--mode", "ecb"], ["--encrypt"], ["--decrypt"], ["--iv", "00"]):
            r = run_dgst("--algorithm", "sha256", "--input", path, *extra)
            assert r.returncode != 0, f"dgst принял {extra}"


def test_cli_missing_file_and_directory():
    """IO-4: понятная ошибка и ненулевой код."""
    r = run_dgst("--algorithm", "sha256", "--input", "no_such_file.bin")
    assert r.returncode == 1 and "does not exist" in r.stderr
    with tempfile.TemporaryDirectory() as tmp:
        r = run_dgst("--algorithm", "sha256", "--input", tmp)
        assert r.returncode == 1 and "directory" in r.stderr


if __name__ == "__main__":
    test_known_answers()
    test_million_a()
    test_block_boundaries_against_hashlib()
    test_chunked_update_equals_single()
    test_digest_is_lowercase_hex()
    test_cli_empty_file()
    test_cli_matches_reference_and_output_format()
    test_cli_rejects_encryption_arguments()
    test_cli_missing_file_and_directory()
    print("Все тесты хэш-функций прошли успешно.")
