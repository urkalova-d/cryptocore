"""Подкоманда dgst: вычисление хэшей файлов (отдельно от шифрования)."""
import argparse
import secrets
import sys

from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256
from src.hash.file_hash import hash_file
from src.mac.hmac import HMAC
from src.mac.cmac import CMAC

# таблица алгоритмов: имя в CLI -> класс хэш-функции
HASH_ALGORITHMS = {
    "sha256": SHA256,
    "sha3-256": SHA3_256,
}


def build_hash_parser():
    # отдельный парсер: аргументы шифрования (--key, --mode, --encrypt,
    # --decrypt, --iv) здесь просто не объявлены, поэтому argparse сам
    # отвергнет их как неизвестные (CLI-3)
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="CryptoCore - вычисление хэша файла (sha256, sha3-256)",
    )
    parser.add_argument(
        "--algorithm", required=False, default=None, choices=sorted(HASH_ALGORITHMS),
        help="Hash algorithm to use (required unless --cmac is given)",
    )
    parser.add_argument(
        "--input", required=True, dest="input_file",
        help="Path to the input file ('-' reads standard input)",
    )
    parser.add_argument(
        "--output", required=False, dest="output_file", default=None,
        help="Write the result to this file instead of stdout",
    )
    # режимы аутентификации сообщений (спринт 5)
    parser.add_argument(
        "--hmac", action="store_true",
        help="Compute HMAC instead of a plain hash (requires --key)",
    )
    parser.add_argument(
        "--cmac", action="store_true",
        help="Compute AES-CMAC instead of a plain hash (requires --key, 16 bytes)",
    )
    parser.add_argument(
        "--key", required=False, default=None,
        help="MAC key as a hexadecimal string (any length for HMAC, 32 hex chars for CMAC)",
    )
    parser.add_argument(
        "--verify", required=False, dest="verify_file", default=None,
        help="Verify the MAC against the value stored in this file",
    )
    return parser


def _check_mac_args(parser, args):
    """Проверить сочетания аргументов и разобрать ключ (CLI-2); ошибки - через parser.error."""
    mac_mode = args.hmac or args.cmac
    if args.hmac and args.cmac:
        parser.error("--hmac and --cmac cannot be used together")
    if not mac_mode:
        if args.algorithm is None:
            parser.error("--algorithm is required")
        if args.key is not None or args.verify_file is not None:
            parser.error("--key and --verify can only be used with --hmac or --cmac")
        return None
    if args.key is None:
        parser.error("--key is required with --hmac/--cmac")
    if args.hmac and args.algorithm is None:
        parser.error("--algorithm is required with --hmac")
    if args.verify_file is not None and args.output_file is not None:
        parser.error("--output cannot be used together with --verify")
    try:
        return bytes.fromhex(args.key)
    except ValueError:
        parser.error("--key must be a valid hexadecimal string")


def _read_expected_mac(path, hex_length):
    """Достать ожидаемое значение MAC из файла (IO-2).

    Формат гибкий: берётся первое слово первой непустой строки, имя файла
    и лишние пробелы игнорируются, регистр букв не важен.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                words = line.split()
                if words:
                    value = words[0].lower()
                    break
            else:
                raise ValueError("file is empty")
        if len(value) != hex_length or any(c not in "0123456789abcdef" for c in value):
            raise ValueError(f"expected {hex_length} hexadecimal characters")
        return value
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"Error: could not read expected MAC from '{path}': {exc}", file=sys.stderr)
        sys.exit(1)


def _write_result(line, output_file):
    if output_file:
        # IO-3: в файл пишется ровно то же, что напечаталось бы в stdout
        try:
            with open(output_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
        except OSError as exc:
            print(f"Error: could not write output file '{output_file}': {exc}",
                  file=sys.stderr)
            sys.exit(1)
    else:
        print(line)


def _run_mac(args, key):
    if args.cmac:
        try:
            mac = CMAC(key)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        name = "CMAC"
    else:
        mac = HMAC(key, args.algorithm)
        name = "HMAC"

    # файл читается порциями той же функцией, что и обычный хэш
    value = hash_file(mac, args.input_file)

    if args.verify_file is not None:
        expected = _read_expected_mac(args.verify_file, len(value))
        # сравнение за постоянное время, чтобы по времени ответа нельзя было подбирать метку
        if secrets.compare_digest(value, expected):
            print(f"[OK] {name} verification successful")
            return
        print(f"[ERROR] {name} verification failed", file=sys.stderr)
        sys.exit(1)

    _write_result(f"{value}  {args.input_file}", args.output_file)


def run_dgst(argv):
    """Выполнить подкоманду dgst; argv — аргументы после слова 'dgst'."""
    parser = build_hash_parser()
    args = parser.parse_args(argv)
    key = _check_mac_args(parser, args)
    if args.hmac or args.cmac:
        _run_mac(args, key)
        return

    hasher = HASH_ALGORITHMS[args.algorithm]()
    digest_hex = hash_file(hasher, args.input_file)

    # формат как у sha256sum: "<хэш>  <путь>" (два пробела), чтобы вывод
    # можно было сравнивать с системными утилитами через diff (CLI-4)
    line = f"{digest_hex}  {args.input_file}"

    _write_result(line, args.output_file)
