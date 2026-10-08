"""Подкоманда dgst: вычисление хэшей файлов (отдельно от шифрования)"""
import argparse
import sys

from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256
from src.hash.file_hash import hash_file

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
        "--algorithm", required=True, choices=sorted(HASH_ALGORITHMS),
        help="Hash algorithm to use",
    )
    parser.add_argument(
        "--input", required=True, dest="input_file",
        help="Path to the input file ('-' reads standard input)",
    )
    parser.add_argument(
        "--output", required=False, dest="output_file", default=None,
        help="Write the result to this file instead of stdout",
    )
    return parser


def run_dgst(argv):
    """Выполнить подкоманду dgst; argv — аргументы после слова 'dgst'."""
    args = build_hash_parser().parse_args(argv)

    hasher = HASH_ALGORITHMS[args.algorithm]()
    digest_hex = hash_file(hasher, args.input_file)

    # формат как у sha256sum: "<хэш>  <путь>" (два пробела), чтобы вывод
    # можно было сравнивать с системными утилитами через diff (CLI-4)
    line = f"{digest_hex}  {args.input_file}"

    if args.output_file:
        # IO-3: в файл пишется ровно то же, что напечаталось бы в stdout
        try:
            with open(args.output_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
        except OSError as exc:
            print(f"Error: could not write output file '{args.output_file}': {exc}",
                  file=sys.stderr)
            sys.exit(1)
    else:
        print(line)
