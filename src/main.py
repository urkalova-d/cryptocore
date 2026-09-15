import sys

from src.cli_parser import parse_args
from src.file_io import read_input_file, write_output_file
from src.modes.ecb import encrypt_ecb, decrypt_ecb

def main(argv=None):
    args = parse_args(argv)

    data = read_input_file(args.input_file)

    try:
        if args.encrypt:
            result = encrypt_ecb(args.key_bytes, data)
        else:
            result = decrypt_ecb(args.key_bytes, data)
    except ValueError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)

    write_output_file(args.output_file, result)


if __name__ == "__main__":
    main()