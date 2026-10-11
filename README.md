# CryptoCore

CLI-инструмент для шифрования и расшифрования файлов алгоритмом AES-128
в режимах ECB, CBC, CFB, OFB и CTR, с собственным криптостойким
генератором случайных чисел для ключей и IV.

Также умеет считать хэши файлов (SHA-256 и SHA3-256, реализованы с нуля) —
подкоманда `dgst`.

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

## Хэширование файлов: подкоманда `dgst`

`dgst` вычисляет хэш (дайджест) файла. Это отдельная подкоманда: аргументы
шифрования (`--key`, `--mode`, `--encrypt`, `--decrypt`, `--iv`) она не
принимает — при их указании инструмент завершится с ошибкой.

| Аргумент | Обязателен | Описание |
|----------|:---:|---|
| `--algorithm` | да | `sha256` или `sha3-256` |
| `--input` | да | путь к файлу; `-` означает стандартный ввод |
| `--output` | нет | записать результат в файл вместо stdout (формат тот же) |

Формат вывода такой же, как у утилит `sha256sum`/`sha3sum`:
`<хэш в нижнем регистре><два пробела><путь>`.

```bash
# Хэш файла
cryptocore dgst --algorithm sha256 --input document.pdf
# 5d5b09f6...  document.pdf

# Другой алгоритм, результат в файл
cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3

# Из стандартного ввода (векторы NIST)
echo -n "abc" | cryptocore dgst --algorithm sha256 --input -
# ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -
```

Файл читается в бинарном режиме порциями по 64 КиБ, поэтому расход памяти
не зависит от размера файла (пустые и очень большие файлы поддерживаются).

### Реализованные алгоритмы

Оба алгоритма написаны с нуля (`src/hash/`), готовые функции `hashlib`
используются только в тестах как эталон.

| Алгоритм | Файл | Стандарт | Конструкция | Стойкость к коллизиям / прообразу |
|----------|------|----------|-------------|:---:|
| SHA-256 | `src/hash/sha256.py` | NIST FIPS 180-4 | Меркла-Дамгарда, блоки 512 бит, 64 раунда | 2^128 / 2^256 |
| SHA3-256 | `src/hash/sha3_256.py` | NIST FIPS 202 | "губка" Keccak-f[1600], rate 1088 бит | 2^128 / 2^256 |

Свойства безопасности:
- Хэш — односторонняя функция: по значению нельзя восстановить файл, а
  малейшее изменение входа меняет около половины бит результата
  (лавинный эффект, проверяется тестом).
- SHA-256 подвержен атаке удлинения сообщения (length extension): по
  `H(m)` и длине `m` можно вычислить `H(m || padding || x)`, не зная `m`.
  Поэтому нельзя использовать `H(секрет || сообщение)` как MAC — для этого
  нужен HMAC. SHA3-256 такой атаке не подвержен благодаря скрытой части
  состояния (capacity).
- Хэш подтверждает целостность только если сам хэш получен по доверенному
  каналу: тот, кто может подменить файл, может подменить и хэш рядом с ним.
- Реализация на чистом Python медленная (порядка 0.3 МБ/с против сотен
  МБ/с у `hashlib`/`sha256sum`) — файл в 1 ГБ хэшируется около часа.

## Проверка корректности

### Автоматические тесты

```bash
python -m tests.test_roundtrip   # базовый round-trip (ECB, из спринта 1)
python -m tests.test_modes       # round-trip для всех режимов + IV + IO-3
python -m tests.test_csprng      # уникальность ключей, распределение бит
python -m tests.test_hash        # векторы NIST, пустой файл, dgst, границы блоков
python -m tests.test_hash_avalanche   # лавинный эффект SHA-256 и SHA3-256
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

### Проверка хэшей (спринт 4)

Сравнение с системными утилитами (вывод должен совпасть байт в байт):

```bash
cryptocore dgst --algorithm sha256 --input large_file.iso > my_hash.txt
sha256sum large_file.iso > system_hash.txt
diff my_hash.txt system_hash.txt        # различий быть не должно

cryptocore dgst --algorithm sha3-256 --input large_file.iso > my_hash3.txt
sha3sum -a 256 large_file.iso > system_hash3.txt     # либо: openssl dgst -sha3-256
diff my_hash3.txt system_hash3.txt
```

В Windows PowerShell эталон для SHA-256: `Get-FileHash file -Algorithm SHA256`
(для SHA3-256 в PowerShell встроенного эталона нет — используйте
`python -c "import hashlib,sys; print(hashlib.sha3_256(open(sys.argv[1],'rb').read()).hexdigest())" file`).

Векторы NIST (SHA-256):

```bash
echo -n "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | cryptocore dgst --algorithm sha256 --input -
# 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1  -
```

Пустой файл: SHA-256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
SHA3-256 = `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`.

Скрипт `test_sprint4.ps1` (Windows PowerShell) прогоняет все эти проверки;
ключ `-Large` добавляет тест на файле больше 1 ГБ (долго, см. выше про скорость).

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
│   ├── hash_cli.py     # подкоманда dgst: аргументы и вывод
│   ├── main.py         # точка входа: dgst либо шифрование (режимы, ключ/IV)
│   ├── hash/
│   │   ├── sha256.py       # SHA-256 с нуля (FIPS 180-4)
│   │   ├── sha3_256.py     # SHA3-256 с нуля (FIPS 202, Keccak)
│   │   └── file_hash.py    # хэширование файла порциями
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
│   ├── test_csprng.py      # уникальность ключей, распределение бит, подготовка NIST-данных
│   ├── test_hash.py        # векторы NIST, пустой файл, dgst, границы блоков
│   └── test_hash_avalanche.py  # лавинный эффект
├── setup.py
├── requirements.txt
└── README.md
```
