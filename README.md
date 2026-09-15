# CryptoCore

CLI-инструмент для шифрования и расшифрования файлов алгоритмом AES-128 в режиме ECB с набивкой PKCS#7.

## Зависимости

- Python 3.8+
- [pycryptodome](https://pypi.org/project/pycryptodome/) >= 3.19

## Установка (сборка)

```bash
git clone <URL_репозитория>
cd cryptocore
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e .
```

После этого команда `cryptocore` становится доступна в активном окружении.

Если не хочется устанавливать пакет, можно просто поставить зависимости и запускать модуль напрямую:

```bash
pip install -r requirements.txt
python -m src.main --algorithm aes --mode ecb --encrypt --key <KEY> --input <IN> --output <OUT>
```

## Использование

```bash
# Шифрование
cryptocore --algorithm aes --mode ecb --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plaintext.txt \
    --output ciphertext.bin

# Расшифрование
cryptocore --algorithm aes --mode ecb --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input ciphertext.bin \
    --output decrypted.txt
```

Аргумент `--output` необязателен: при шифровании по умолчанию используется
`<input>.enc`, при расшифровании — `ciphertext.enc.dec`.

Ключ (`--key`) задаётся в виде hex-строки, представляющей ровно 16 байт (AES-128).

## Проверка корректности (round-trip)

```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f \
    --input original.txt --output cipher.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f \
    --input cipher.bin --output restored.txt
diff original.txt restored.txt   # не должно быть различий
```

Автоматический тест этого сценария:

```bash
python -m tests.test_roundtrip
```

## Сверка с OpenSSL

Для файлов, длина которых кратна 16 байтам, результат можно сверить с OpenSSL:

```bash
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f \
    -in plaintext.txt -out ciphertext_openssl.bin -nopad
```

## Структура проекта

```
cryptocore/
├── src/
│   ├── cli_parser.py   # разбор и валидация аргументов CLI
│   ├── file_io.py      # чтение/запись файлов
│   ├── main.py         # точка входа
│   └── modes/
│       └── ecb.py      # ECB-режим и PKCS#7 padding поверх AES-примитива
├── tests/
│   └── test_roundtrip.py
├── setup.py
├── requirements.txt
└── README.md
```
