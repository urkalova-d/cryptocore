# CryptoCore

CLI-инструмент для шифрования и расшифрования файлов алгоритмом AES-128
в режимах ECB, CBC, CFB, OFB и CTR.

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

## Поддерживаемые режимы

| Режим | Требует padding | Требует IV | Комментарий |
|-------|:---:|:---:|---|
| `ecb` | да (PKCS#7) | нет | базовый режим из спринта 1, небезопасен для повторяющихся блоков |
| `cbc` | да (PKCS#7) | да | классическое сцепление блоков через XOR |
| `cfb` | нет | да | потоковый режим, сегмент = полный блок (128 бит) |
| `ofb` | нет | да | потоковый режим, keystream не зависит от данных |
| `ctr` | нет | да | потоковый режим, IV используется как стартовое значение счётчика |

## Использование

```bash
# Шифрование (ECB — IV не используется)
cryptocore --algorithm aes --mode ecb --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plaintext.txt \
    --output ciphertext.bin

# Шифрование в CBC/CFB/OFB/CTR — IV генерируется автоматически и
# записывается в первые 16 байт выходного файла. Передавать --iv при
# шифровании нельзя — это ошибка.
cryptocore --algorithm aes --mode cbc --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plaintext.txt \
    --output ciphertext.bin

# Расшифрование — если --iv не указан, IV читается из первых 16 байт
# входного файла (формат такой же, как при шифровании).
cryptocore --algorithm aes --mode cbc --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input ciphertext.bin \
    --output decrypted.txt

# Расшифрование с явно заданным IV (например, шифротекст без встроенного
# IV — так, как отдаёт голый OpenSSL с флагом -iv).
cryptocore --algorithm aes --mode cbc --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --iv AABBCCDDEEFF00112233445566778899 \
    --input ciphertext_body.bin \
    --output decrypted.txt
```

Аргумент `--output` необязателен: при шифровании по умолчанию используется
`<input>.enc`, при расшифровании — `ciphertext.enc.dec`.

Ключ (`--key`) и IV (`--iv`) задаются как hex-строки ровно на 16 байт (32 hex-символа).

### Формат файла шифротекста (для режимов с IV)

```
<16 байт IV><байты шифротекста>
```

## Проверка корректности (round-trip)

```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f \
    --input original.txt --output cipher.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f \
    --input cipher.bin --output restored.txt
diff original.txt restored.txt   # не должно быть различий
```

Автоматические тесты (round-trip для всех режимов и граничных длин,
явный `--iv`, обработка слишком короткого файла):

```bash
python -m tests.test_modes
python -m tests.test_roundtrip
```

## Сверка с OpenSSL

### ECB (файл кратен 16 байтам)

```bash
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f \
    -in plaintext.txt -out ciphertext_openssl.bin -nopad
```

### Наш инструмент шифрует → OpenSSL расшифровывает (пример для CBC)

```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090A0B0C0D0E0F \
    --input plain.txt --output cipher.bin

# извлекаем IV (первые 16 байт) и тело шифротекста отдельно
dd if=cipher.bin of=iv.bin bs=16 count=1
dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1

openssl enc -aes-128-cbc -d -K 000102030405060708090A0B0C0D0E0F \
    -iv "$(xxd -p iv.bin | tr -d '\n')" \
    -in ciphertext_only.bin -out decrypted_by_openssl.txt

diff plain.txt decrypted_by_openssl.txt   # не должно быть различий
```

### OpenSSL шифрует → наш инструмент расшифровывает (пример для CBC)

```bash
openssl enc -aes-128-cbc -K 000102030405060708090A0B0C0D0E0F \
    -iv AABBCCDDEEFF00112233445566778899 \
    -in plain.txt -out openssl_cipher.bin

cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090A0B0C0D0E0F \
    --iv AABBCCDDEEFF00112233445566778899 \
    --input openssl_cipher.bin --output decrypted.txt

diff plain.txt decrypted.txt   # не должно быть различий
```

То же самое повторяется для `cfb`, `ofb`, `ctr` — меняется только имя режима
в `--mode`/`-aes-128-<mode>`.

## Структура проекта

```
cryptocore/
├── src/
│   ├── cli_parser.py   # разбор и валидация аргументов CLI (в т.ч. --iv)
│   ├── file_io.py      # чтение/запись файлов
│   ├── main.py         # точка входа: диспетчеризация режимов + логика IV
│   └── modes/
│       ├── common.py   # общие утилиты: XOR, PKCS#7, доступ к AES-примитиву
│       ├── ecb.py
│       ├── cbc.py
│       ├── cfb.py
│       ├── ofb.py
│       └── ctr.py
├── tests/
│   ├── test_roundtrip.py   # round-trip тест из спринта 1 (ECB)
│   └── test_modes.py       # round-trip для всех режимов + IV + IO-3
├── setup.py
├── requirements.txt
└── README.md
```
