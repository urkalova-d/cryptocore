# CryptoCore

CLI-инструмент для шифрования и расшифрования файлов алгоритмом AES-128
в режимах ECB, CBC, CFB, OFB и CTR, с собственным криптостойким
генератором случайных чисел для ключей и IV.

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

Без установки пакета — через requirements.txt и прямой вызов модуля:

```bash
pip install -r requirements.txt
python -m src.main --algorithm aes --mode ecb --encrypt --key <KEY> --input <IN> --output <OUT>
```

## Поддерживаемые режимы

| Режим | Требует padding | Требует IV | Комментарий |
|-------|:---:|:---:|---|
| `ecb` | да (PKCS#7) | нет | базовый режим, небезопасен для повторяющихся блоков |
| `cbc` | да (PKCS#7) | да | классическое сцепление блоков через XOR |
| `cfb` | нет | да | потоковый режим, сегмент = полный блок (128 бит) |
| `ofb` | нет | да | потоковый режим, keystream не зависит от данных |
| `ctr` | нет | да | потоковый режим, IV используется как стартовое значение счётчика |

## Ключ: явный или сгенерированный автоматически

При **шифровании** `--key` теперь необязателен:

```bash
# Ключ не передан - инструмент сам сгенерирует случайный 16-байтовый ключ,
# напечатает его в stdout и продолжит шифрование этим ключом.
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
# [INFO] Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
```

Сгенерированный ключ выводится **ровно один раз**, в сам файл шифротекста
он не попадает — это единственное место, где его можно увидеть, поэтому
его нужно сохранить (например, скопировать в менеджер паролей) сразу же.

При **расшифровке** `--key` по-прежнему обязателен — без него инструмент
завершится с ошибкой:

```bash
cryptocore --algorithm aes --mode ctr --decrypt --key 1a2b3c4d5e6f7890fedcba9876543210 \
    --input ciphertext.bin --output decrypted.txt
```

### Предупреждение о слабом ключе

Если явно передан заведомо слабый ключ (все байты одинаковые, либо байты
идут строго по возрастанию/убыванию — как, например, учебный ключ
`000102030405060708090a0b0c0d0e0f`), инструмент печатает предупреждение
в stderr, но **не блокирует** выполнение:

```
[WARNING] Weak key detected: bytes form a sequential pattern.
```

Это не полноценная проверка криптостойкости (её в принципе не существует
для одного конкретного значения ключа), а подсказка для самых очевидных
учебных/небрежных случаев.

## IV при шифровании/расшифровке

```bash
# Шифрование в CBC/CFB/OFB/CTR — IV генерируется автоматически и
# записывается в первые 16 байт выходного файла. Передавать --iv при
# шифровании нельзя — это ошибка.
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f \
    --input plaintext.txt --output ciphertext.bin

# Расшифрование — если --iv не указан, IV читается из первых 16 байт
# входного файла.
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f \
    --input ciphertext.bin --output decrypted.txt

# Расшифрование с явно заданным IV (например, шифротекст без встроенного
# IV - так, как отдаёт голый OpenSSL с флагом -iv).
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f \
    --iv AABBCCDDEEFF00112233445566778899 --input ciphertext_body.bin --output decrypted.txt
```

Формат файла шифротекста (для режимов с IV): `<16 байт IV><шифротекст>`.

## О генераторе случайных чисел (CSPRNG)

Весь проект берёт случайность из одного места — `src/csprng.py`, функция
`generate_random_bytes(num_bytes)`. Она используется и для генерации
ключа (когда `--key` не передан), и для генерации IV во всех режимах,
где он нужен.

**Источник случайности:** `os.urandom()` — обёртка над генератором
случайных чисел операционной системы (на Linux это `getrandom()`/
`/dev/urandom`, на Windows — `BCryptGenRandom`). Это криптографически
стойкий источник: в отличие от модуля `random` (детерминированный
Mersenne Twister, предсказуемый при известном состоянии), вывод
`os.urandom()` нельзя предсказать или воспроизвести, даже зная
предыдущие значения. Именно поэтому модуль `random` нигде в проекте
не используется — только `os.urandom()`.

## Проверка корректности

### Автоматические тесты

```bash
python -m tests.test_roundtrip   # базовый round-trip (ECB, из спринта 1)
python -m tests.test_modes       # round-trip для всех режимов + IV + IO-3
python -m tests.test_csprng      # уникальность ключей, распределение бит
```

### Ручная проверка генерации ключа (TEST-1)

```bash
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output cipher.bin
# скопируйте напечатанный ключ, затем:
cryptocore --algorithm aes --mode ctr --decrypt --key <напечатанный_ключ> \
    --input cipher.bin --output decrypted.txt
diff plaintext.txt decrypted.txt   # не должно быть различий
```

### Сверка с OpenSSL (TEST-5, интероперабельность из спринта 2 без изменений)

```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090A0B0C0D0E0F \
    --input plain.txt --output cipher.bin
dd if=cipher.bin of=iv.bin bs=16 count=1
dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1
openssl enc -aes-128-cbc -d -K 000102030405060708090A0B0C0D0E0F \
    -iv "$(xxd -p iv.bin | tr -d '\n')" -in ciphertext_only.bin -out decrypted_by_openssl.txt
diff plain.txt decrypted_by_openssl.txt
```

(Для других режимов — меняем `cbc` на `cfb`/`ofb`/`ctr` в обеих командах.)

### NIST Statistical Test Suite (TEST-3)

Статистический аудит самого источника случайности выполняется внешним
инструментом — [NIST Statistical Test Suite (STS)](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software).

1. Сгенерировать достаточно большой файл случайных данных (рекомендуется 1-100 МБ):

   ```bash
   python -c "from src.csprng import generate_random_bytes; \
       open('nist_test_data.bin', 'wb').write(generate_random_bytes(10_000_000))"
   ```

   Либо через вспомогательную функцию в тестах (пишет чанками, без
   удержания всего файла в памяти разом):

   ```bash
   python -c "from tests.test_csprng import prepare_nist_test_data; prepare_nist_test_data()"
   ```

2. Скачать и собрать NIST STS (C-версия) с сайта NIST, либо использовать
   готовую сборку.

3. Запустить набор тестов на сгенерированном файле:

   ```bash
   ./assess 10000000
   # далее отвечать на интерактивные вопросы assess, указав путь
   # к nist_test_data.bin и 0 (бинарный формат)
   ```

4. **Критерий успеха:** подавляющее большинство из 15 тестов должны
   показать p-value ≥ 0.01. Единичные "пограничные" неудачи статистически
   ожидаемы даже для качественного CSPRNG (это следствие самой природы
   статистических тестов — у них есть предопределённый уровень ложных
   срабатываний); массовые провалы по многим тестам означали бы
   реальный дефект генератора.

5. Результаты прогона рекомендуется сохранить рядом (например, в
   `TESTING.md`) вместе с датой и версией NIST STS, которой пользовались.

## Структура проекта

```
cryptocore/
├── src/
│   ├── cli_parser.py   # разбор и валидация аргументов CLI (ключ, --iv)
│   ├── csprng.py       # криптостойкий генератор случайных чисел
│   ├── file_io.py      # чтение/запись файлов
│   ├── main.py         # точка входа: диспетчеризация режимов, ключ/IV
│   └── modes/
│       ├── common.py   # общие утилиты: XOR, PKCS#7, доступ к AES-примитиву
│       ├── ecb.py
│       ├── cbc.py
│       ├── cfb.py
│       ├── ofb.py
│       └── ctr.py
├── tests/
│   ├── test_roundtrip.py   # round-trip тест из спринта 1 (ECB)
│   ├── test_modes.py       # round-trip для всех режимов + IV + IO-3
│   └── test_csprng.py      # уникальность ключей, распределение бит, подготовка NIST-данных
├── setup.py
├── requirements.txt
└── README.md
```
