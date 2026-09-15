""" функции для ввода/вывода """
import sys

def read_input_file(path):
    """Чтение всего содержимого файла path как байты или завершение работы с ошибкой"""
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Ошибка: входной файл '{path}' не существует.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Ошибка: входной файл '{path}' недоступен для чтения.", file=sys.stderr)
        sys.exit(1)
    except IsADirectoryError:
        print(f"Ошибка: путь '{path}' — это каталог, а не файл.", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"Ошибка: не удалось прочитать входной файл '{path}': {exc}", file=sys.stderr)
        sys.exit(1)


def write_output_file(path, data):
    """запись data  в path или завершение работы с ошибкой"""
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as exc:
        print(f"Ошибка: не удалось записать выходной файл '{path}': {exc}", file=sys.stderr)
        sys.exit(1)