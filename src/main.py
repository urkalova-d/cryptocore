
import sys

from src.cli_parser import parse_args
from src.file_io import read_input_file, write_output_file
from src.csprng import generate_random_bytes
from src.modes.common import BLOCK_SIZE
from src.modes.ecb import encrypt_ecb, decrypt_ecb
from src.modes.cbc import encrypt_cbc, decrypt_cbc
from src.modes.cfb import encrypt_cfb, decrypt_cfb
from src.modes.ofb import encrypt_ofb, decrypt_ofb
from src.modes.ctr import encrypt_ctr, decrypt_ctr

#таблица режимов
MODES = {
    "ecb": {"needs_iv": False, "encrypt": encrypt_ecb, "decrypt": decrypt_ecb},
    "cbc": {"needs_iv": True, "encrypt": encrypt_cbc, "decrypt": decrypt_cbc},
    "cfb": {"needs_iv": True, "encrypt": encrypt_cfb, "decrypt": decrypt_cfb},
    "ofb": {"needs_iv": True, "encrypt": encrypt_ofb, "decrypt": decrypt_ofb},
    "ctr": {"needs_iv": True, "encrypt": encrypt_ctr, "decrypt": decrypt_ctr},
}


def main(argv=None):
    args = parse_args(argv)
    mode = MODES[args.mode]

    #ключ не передан при шифровании —генерируем его сами через CSPRNG и один раз печатаем в stdout.
    if args.encrypt and args.key_bytes is None:
        args.key_bytes = generate_random_bytes(BLOCK_SIZE)
        print(f"[INFO] Generated random key: {args.key_bytes.hex()}")
        # сгенерированный ключ нигде, кроме stdout, не сохраняется —
        # в частности, он не попадёт ни в файл шифротекста, ни в лог

    data = read_input_file(args.input_file)

    try:
        if args.encrypt:
            result = _do_encrypt(mode, args, data)
        else:
            result = _do_decrypt(mode, args, data)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    write_output_file(args.output_file, result)


def _do_encrypt(mode, args, plaintext):
    if not mode["needs_iv"]:
        return mode["encrypt"](args.key_bytes, plaintext)

    #вектор инициализации тоже генерируется через единый CSPRNG-модуль,а не напрямую через os.urandom
    iv = generate_random_bytes(BLOCK_SIZE)
    ciphertext = mode["encrypt"](args.key_bytes, iv, plaintext)

    #  формат файла не изменился - IV по-прежнему приклеивается в начало
    return iv + ciphertext


def _do_decrypt(mode, args, file_data):
    if not mode["needs_iv"]:
        return mode["decrypt"](args.key_bytes, file_data)

    if args.iv_bytes is not None:
        # пользователь явно передает вектор инциалтзации через --iv,весь файл это шифротекст
        iv = args.iv_bytes
        ciphertext = file_data
    else:
        # вектор инициализации не передан, чтение первых 16 байт входного файла
        if len(file_data) < BLOCK_SIZE:
            raise ValueError(
                f"Input file is too short to contain a {BLOCK_SIZE}-byte IV "
                f"(got {len(file_data)} bytes)"
            )
        iv = file_data[:BLOCK_SIZE]
        ciphertext = file_data[BLOCK_SIZE:]

    return mode["decrypt"](args.key_bytes, iv, ciphertext)


if __name__ == "__main__":
    main()
