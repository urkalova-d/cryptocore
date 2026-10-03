"""Разбор и валидация аргументов командной строки """
import argparse
import sys

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

    #--key стал необязательным на уровне argparse
    #при --decrypt проверяется отдельно в validate_args,тк argparse не умеет условную обязательность "required только если --decrypt"
    parser.add_argument(
        "--key", required=False, default=None,
        help="AES-128 key as a 32-character hexadecimal string (16 bytes). "
             "Optional for --encrypt (a random key is generated if omitted); "
             "mandatory for --decrypt.",
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
    #--key стал обязательным
    # при расшифровке ключ обязателен
    if args.decrypt and args.key is None:
        parser.error("--key is required for decryption")

    # при шифровании ключ можно не передавать — его сгенерирует main через CSPRNG
    args.key_bytes = None
    if args.key is not None:
        try:
            key_bytes = bytes.fromhex(args.key)
        except ValueError:
            parser.error("--key must be a valid hexadecimal string")
            return

        if len(key_bytes) != 16:
            parser.error(
                f"--key must represent exactly 16 bytes for AES-128 "
                f"(got {len(key_bytes)} bytes)"
            )

        args.key_bytes = key_bytes
        _warn_if_weak_key(key_bytes)

    #  валидация вектора инициализации
    mode_needs_iv = args.mode in MODES_WITH_IV

    if args.encrypt and args.iv is not None:
        # при шифровании вектора инициализации генерируется автоматически, вручную задавать нельзя
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
    # если --iv не передан при decrypt для режима с IV — это нормально,
    # IV будет прочитан из первых 16 байт входного файла

    if not args.output_file:
        args.output_file = derive_default_output(args)


def _warn_if_weak_key(key_bytes: bytes):
    if len(set(key_bytes)) == 1:
        print(
            f"[WARNING] Weak key detected: all bytes are the same (0x{key_bytes[0]:02x}).",
            file=sys.stderr,
        )
        return

    is_ascending = all(
        key_bytes[i] + 1 == key_bytes[i + 1] for i in range(len(key_bytes) - 1)
    )
    is_descending = all(
        key_bytes[i] - 1 == key_bytes[i + 1] for i in range(len(key_bytes) - 1)
    )
    if is_ascending or is_descending:
        print("[WARNING] Weak key detected: bytes form a sequential pattern.", file=sys.stderr)


def derive_default_output(args):
    if args.encrypt:
        return f"{args.input_file}.enc"
    return "ciphertext.enc.dec"
