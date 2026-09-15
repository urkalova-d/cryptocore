"""Разбор и валидация аргументов командной строки """
import argparse


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="CryptoCore — инструмент шифрования/расшифрования AES-128 ECB",
    )
    parser.add_argument(
        "--algorithm", required=True, choices=["aes"],
        help="Алгоритм шифрования (в этом спринте поддерживается только 'aes')",
    )
    parser.add_argument(
        "--mode", required=True, choices=["ecb"],
        help="Режим работы (в этом спринте поддерживается только 'ecb')",
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true", help="Зашифровать входной файл")
    operation.add_argument("--decrypt", action="store_true", help="Расшифровать входной файл")

    parser.add_argument(
        "--key", required=True,
        help="Ключ AES-128 в виде 32-символьной шестнадцатеричной строки (16 байт)",
    )
    parser.add_argument(
        "--input", required=True, dest="input_file",
        help="Путь к входному файлу",
    )
    parser.add_argument(
        "--output", required=False, dest="output_file", default=None,
        help="Путь к выходному файлу (необязательно; если не указан — имя выводится по умолчанию)",
    )
    return parser


def parse_args(argv=None):
    """разоборка и проверка аргументов . при ошибке завершает работу с ненулевым кодом"""
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    return args


def validate_args(parser, args):
    # ключ должен быть корректной hex строкой
    try:
        key_bytes = bytes.fromhex(args.key)
    except ValueError:
        parser.error("--key должен быть корректной шестнадцатеричной строкой")
        return

    #для aes128 ключ должен быть длиной 16байт
    if len(key_bytes) != 16:
        parser.error(
            f"--key должен представлять ровно 16 байт для AES-128 "
            f"(получено {len(key_bytes)} байт)"
        )

    args.key_bytes = key_bytes

    #если выходной файл не задан, вывести имя по умолчанию
    if not args.output_file:
        args.output_file = derive_default_output(args)


def derive_default_output(args):
    if args.encrypt:
        return f"{args.input_file}.enc"
    return "ciphertext.enc.dec"