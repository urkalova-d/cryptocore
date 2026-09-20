"""Разбор и валидация аргументов командной строки"""
import argparse

from src.modes.common import BLOCK_SIZE
MODES_WITH_IV = {"cbc", "cfb", "ofb", "ctr"}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="CryptoCore - AES-128 encryption/decryption tool (ECB/CBC/CFB/OFB/CTR)",
    )
    parser.add_argument(
        "--algorithm", required=True, choices=["aes"],
        help="Cipher algorithm to use (only 'aes' is supported this sprint)",
    )
    parser.add_argument(
        "--mode", required=True, choices=["ecb", "cbc", "cfb", "ofb", "ctr"],
        help="Mode of operation",
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true", help="Encrypt the input file")
    operation.add_argument("--decrypt", action="store_true", help="Decrypt the input file")

    parser.add_argument(
        "--key", required=True,
        help="AES-128 key as a 32-character hexadecimal string (16 bytes)",
    )
    parser.add_argument(
        "--iv", required=False, default=None,
        help="IV as a 32-character hexadecimal string (16 bytes). "
             "Only valid with --decrypt; for --encrypt the IV is generated automatically.",
    )
    parser.add_argument(
        "--input", required=True, dest="input_file",
        help="Path to the input file",
    )
    parser.add_argument(
        "--output", required=False, dest="output_file", default=None,
        help="Path to the output file (optional, a default is derived if omitted)",
    )
    return parser


def parse_args(argv=None):
    """разоборка и проверка аргументов, при ошибке завершает работу с ненулевым кодом"""
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    return args


def validate_args(parser, args):
    #ключ должен быть корректной hex строкой
    try:
        key_bytes = bytes.fromhex(args.key)
    except ValueError:
        parser.error("--key must be a valid hexadecimal string")
        return  # для aes128 ключ должен быть длиной 16байт

    if len(key_bytes) != 16:
        parser.error(
            f"--key must represent exactly 16 bytes for AES-128 "
            f"(got {len(key_bytes)} bytes)"
        )

    args.key_bytes = key_bytes

    # валидация вектора инциализации
    mode_needs_iv = args.mode in MODES_WITH_IV

    if args.encrypt and args.iv is not None:
        #при шифровании вектор генерируется автоматически, вручную задавать нельзя
        parser.error("--iv must not be provided during encryption (IV is generated automatically)")

    if not mode_needs_iv and args.iv is not None:
        parser.error(f"--iv is not applicable to mode '{args.mode}'")

    args.iv_bytes = None
    if args.decrypt and args.iv is not None:
        try:
            iv_bytes = bytes.fromhex(args.iv)
        except ValueError:
            parser.error("--iv must be a valid hexadecimal string")
            return

        if len(iv_bytes) != BLOCK_SIZE:
            parser.error(
                f"--iv must represent exactly {BLOCK_SIZE} bytes "
                f"(got {len(iv_bytes)} bytes)"
            )

        args.iv_bytes = iv_bytes

    #если выходной файл не задан, вывести имя по умолчанию
    if not args.output_file:
        args.output_file = derive_default_output(args)


def derive_default_output(args):
    if args.encrypt:
        return f"{args.input_file}.enc"
    return "ciphertext.enc.dec"
