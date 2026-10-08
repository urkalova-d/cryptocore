"""Вычисление хэша файла порциями (HASH-5, IO-1, IO-2, IO-4)."""
import os
import sys

CHUNK_SIZE = 65536  # размер порции чтения: память не зависит от размера файла


def _consume(stream, hasher):
    """Читать поток порциями и подавать их в hasher.update()."""
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        hasher.update(chunk)


def hash_file(hasher, path):
    """Посчитать хэш файла `path` ('-' означает стандартный ввод).

    Файл читается в бинарном режиме и порциями, целиком в память не
    загружается. При ошибке доступа печатает понятное сообщение в stderr
    и завершает программу с ненулевым кодом.
    """
    if path == "-":
        _consume(sys.stdin.buffer, hasher)
        return hasher.hexdigest()

    # каталог проверяем явно: на Windows open() для каталога выдаёт
    # PermissionError, а не IsADirectoryError, и сообщение было бы неточным
    if os.path.isdir(path):
        print(f"Error: input path '{path}' is a directory, not a file.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path, "rb") as f:
            _consume(f, hasher)
    except FileNotFoundError:
        print(f"Error: input file '{path}' does not exist.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: input file '{path}' is not readable.", file=sys.stderr)
        sys.exit(1)
    except IsADirectoryError:
        print(f"Error: input path '{path}' is a directory, not a file.", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"Error: could not read input file '{path}': {exc}", file=sys.stderr)
        sys.exit(1)

    return hasher.hexdigest()
