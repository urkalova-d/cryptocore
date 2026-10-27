"""dgst --hmac / --cmac / --verify через командную строку (TEST-2 .. TEST-7)."""
import hashlib
import hmac as std_hmac
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = "00112233445566778899aabbccddeeff"


def dgst(*args):
    return subprocess.run([sys.executable, "-m", "src.main", "dgst", *args],
                          capture_output=True, text=True, cwd=ROOT)


class TestMacCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name, data=None):
        p = os.path.join(self.tmp.name, name)
        if data is not None:
            with open(p, "wb") as f:
                f.write(data)
        return p

    def hmac_args(self, file, key=KEY, *extra):
        return ["--algorithm", "sha256", "--hmac", "--key", key, "--input", file, *extra]

    def test_rfc_4231_case_1(self):
        f = self.path("t.txt", b"Hi There")
        r = dgst(*self.hmac_args(f, "0b" * 20))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.split()[0],
                         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        self.assertTrue(r.stdout.rstrip().endswith(f))      # формат: HMAC  путь

    def test_verify_ok(self):
        f = self.path("m.txt", b"original content\n")
        mac_file = self.path("m.hmac")
        self.assertEqual(dgst(*self.hmac_args(f), "--output", mac_file).returncode, 0)
        r = dgst(*self.hmac_args(f), "--verify", mac_file)
        self.assertEqual(r.returncode, 0)
        self.assertIn("[OK]", r.stdout)

    def test_verify_flexible_format(self):
        f = self.path("m.txt", b"data")
        value = std_hmac.new(bytes.fromhex(KEY), b"data", "sha256").hexdigest()
        for text in (value, value.upper() + "\n", f"  {value}   whatever name.txt\n\n", f"\n{value} x"):
            with self.subTest(text=text[:10]):
                r = dgst(*self.hmac_args(f), "--verify", self.path("e.txt", text.encode()))
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_tamper_file(self):
        f = self.path("m.txt", b"original content\n")
        mac_file = self.path("m.hmac")
        dgst(*self.hmac_args(f), "--output", mac_file)
        self.path("m.txt", b"original contenT\n")          # меняется один байт
        r = dgst(*self.hmac_args(f), "--verify", mac_file)
        self.assertEqual(r.returncode, 1)
        self.assertIn("[ERROR] HMAC verification failed", r.stderr)

    def test_wrong_key(self):
        f = self.path("m.txt", b"content")
        mac_file = self.path("m.hmac")
        dgst(*self.hmac_args(f), "--output", mac_file)
        r = dgst(*self.hmac_args(f, "ff" + KEY[2:]), "--verify", mac_file)
        self.assertEqual(r.returncode, 1)
        self.assertIn("verification failed", r.stderr)

    def test_key_sizes_against_hashlib(self):
        f = self.path("m.txt", b"some message")
        for key_len in (16, 64, 100):
            key = os.urandom(key_len)
            r = dgst(*self.hmac_args(f, key.hex()))
            self.assertEqual(r.stdout.split()[0],
                             std_hmac.new(key, b"some message", "sha256").hexdigest())

    def test_empty_file(self):
        f = self.path("empty.bin", b"")
        r = dgst(*self.hmac_args(f))
        self.assertEqual(r.stdout.split()[0],
                         std_hmac.new(bytes.fromhex(KEY), b"", "sha256").hexdigest())

    def test_multi_chunk_file(self):
        data = os.urandom(200_000)                          # больше 3 порций по 64 КиБ
        f = self.path("big.bin", data)
        r = dgst(*self.hmac_args(f))
        self.assertEqual(r.stdout.split()[0],
                         std_hmac.new(bytes.fromhex(KEY), data, "sha256").hexdigest())

    def test_stdin(self):
        r = subprocess.run([sys.executable, "-m", "src.main", "dgst", "--algorithm", "sha256",
                            "--hmac", "--key", KEY, "--input", "-"],
                           input=b"abc", capture_output=True, cwd=ROOT)
        self.assertEqual(r.stdout.split()[0].decode(),
                         std_hmac.new(bytes.fromhex(KEY), b"abc", "sha256").hexdigest())

    def test_output_file_format(self):
        f = self.path("m.txt", b"abc")
        out = self.path("out.txt")
        dgst(*self.hmac_args(f), "--output", out)
        with open(out, encoding="utf-8") as fh:
            value, name = fh.read().split()
        self.assertEqual(name, f)
        self.assertEqual(len(value), 64)

    def test_argument_errors(self):
        f = self.path("m.txt", b"abc")
        cases = [
            ["--algorithm", "sha256", "--hmac", "--input", f],                       # нет --key
            ["--algorithm", "sha256", "--hmac", "--key", "abc", "--input", f],       # нечётная длина hex
            ["--algorithm", "sha256", "--hmac", "--key", "zz", "--input", f],        # не hex
            ["--algorithm", "sha256", "--key", KEY, "--input", f],                   # --key без --hmac
            ["--algorithm", "sha256", "--verify", f, "--input", f],                  # --verify без MAC
            ["--algorithm", "sha256", "--hmac", "--cmac", "--key", KEY, "--input", f],
            ["--algorithm", "sha256", "--hmac", "--key", KEY, "--input", f,
             "--verify", f, "--output", f],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertNotEqual(dgst(*args).returncode, 0)

    def test_verify_bad_expected_file(self):
        f = self.path("m.txt", b"abc")
        for name, content in (("missing", None), ("empty", b""), ("junk", b"not-a-hex-value\n"),
                              ("short", b"abcd\n")):
            with self.subTest(name=name):
                p = self.path(name + ".txt", content) if content is not None else self.path("nope.txt")
                r = dgst(*self.hmac_args(f), "--verify", p)
                self.assertEqual(r.returncode, 1)

    def test_plain_hash_unchanged(self):
        f = self.path("m.txt", b"abc")
        r = dgst("--algorithm", "sha256", "--input", f)
        self.assertEqual(r.stdout.split()[0], hashlib.sha256(b"abc").hexdigest())
        self.assertNotEqual(dgst("--input", f).returncode, 0)   # без --algorithm по-прежнему ошибка

    def test_cmac_cli(self):
        key = "2b7e151628aed2a6abf7158809cf4f3c"
        msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        f = self.path("c.bin", msg)
        r = dgst("--cmac", "--key", key, "--input", f)
        self.assertEqual(r.stdout.split()[0], "070a16b46b4d4144f79bdd9dd04a287c")
        mac_file = self.path("c.mac")
        dgst("--cmac", "--key", key, "--input", f, "--output", mac_file)
        ok = dgst("--cmac", "--key", key, "--input", f, "--verify", mac_file)
        self.assertEqual(ok.returncode, 0)
        self.assertIn("[OK] CMAC", ok.stdout)
        self.assertEqual(dgst("--cmac", "--key", "00", "--input", f).returncode, 1)  # ключ не 16 байт


if __name__ == "__main__":
    unittest.main()
