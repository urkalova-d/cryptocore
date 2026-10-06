

function Test-FilesEqual($a, $b) {
    # Сравниваем файлы по хэшу - надежнее, чем построчное сравнение
    (Get-FileHash $a -Algorithm SHA256).Hash -eq (Get-FileHash $b -Algorithm SHA256).Hash
}

function New-RandomFile($path, $n) {
    # RNGCryptoServiceProvider вместо RandomNumberGenerator.Fill -
    # последний недоступен в Windows PowerShell 5.1 (.NET Framework)
    $bytes = New-Object byte[] $n
    if ($n -gt 0) {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($bytes)
        $rng.Dispose()
    }
    [System.IO.File]::WriteAllBytes($path, $bytes)
}

function Get-HexPrefix($path, $n) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    -join ($bytes[0..($n - 1)] | ForEach-Object { $_.ToString("x2") })
}

function Split-IvAndBody($cipherPath, $ivOutPath, $bodyOutPath) {
    $bytes = [System.IO.File]::ReadAllBytes($cipherPath)
    [System.IO.File]::WriteAllBytes($ivOutPath, $bytes[0..15])
    [System.IO.File]::WriteAllBytes($bodyOutPath, $bytes[16..($bytes.Length - 1)])
}

$KEY = "9f2b7a1e4c6d8035f10a2e9b7c4d1685"   # обычный (не слабый) тестовый ключ
Set-Content -Path plain.txt -Value "Testovoe soobschenie dlya proverki CryptoCore." -NoNewline

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 1. Avtotesty (roundtrip, modes, csprng) ===" -ForegroundColor Cyan
python -m tests.test_roundtrip
python -m tests.test_modes
python -m tests.test_csprng

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 2. Regressiya: roundtrip po vsem rezhimam s yavnym klyuchom ===" -ForegroundColor Cyan
foreach ($mode in @("ecb", "cbc", "cfb", "ofb", "ctr")) {
    cryptocore --algorithm aes --mode $mode --encrypt --key $KEY --input plain.txt --output "cipher_$mode.bin"
    cryptocore --algorithm aes --mode $mode --decrypt --key $KEY --input "cipher_$mode.bin" --output "decrypted_$mode.txt"

    if (Test-FilesEqual plain.txt "decrypted_$mode.txt") {
        Write-Host "OK: $mode" -ForegroundColor Green
    } else {
        Write-Host "FAIL: $mode" -ForegroundColor Red
    }
}

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 3. TEST-1: shifrovanie BEZ --key (avtogeneratsiya) ===" -ForegroundColor Cyan

$genOutput = cryptocore --algorithm aes --mode ctr --encrypt --input plain.txt --output gen_cipher.bin 2>&1
Write-Host "Vyvod instrumenta:"
Write-Host $genOutput

# Ищем hex-строку из 32 символов в выводе - это и есть сгенерированный ключ
$match = [regex]::Match(($genOutput -join " "), "[0-9a-f]{32}")
if (-not $match.Success) {
    Write-Host "FAIL: v vyvode ne naiden sgenerirovannyi klyuch" -ForegroundColor Red
} else {
    $genKey = $match.Value
    Write-Host "Izvlechennyi klyuch: $genKey"

    cryptocore --algorithm aes --mode ctr --decrypt --key $genKey --input gen_cipher.bin --output gen_decrypted.txt

    if (Test-FilesEqual plain.txt gen_decrypted.txt) {
        Write-Host "OK: roundtrip s sgenerirovannym klyuchom" -ForegroundColor Green
    } else {
        Write-Host "FAIL: roundtrip s sgenerirovannym klyuchom" -ForegroundColor Red
    }
}

# Ключ не должен попадать в сам файл шифротекста (KEY-3)
if ($match.Success) {
    $cipherBytes = [System.IO.File]::ReadAllBytes("gen_cipher.bin")
    $keyBytes = -split ($match.Value -replace '..', '$0 ') | ForEach-Object { [Convert]::ToByte($_, 16) }
    $cipherHex = -join ($cipherBytes | ForEach-Object { $_.ToString("x2") })
    if ($cipherHex.Contains($match.Value)) {
        Write-Host "FAIL: sgenerirovannyi klyuch obnaruzhen vnutri faila shifrotexta!" -ForegroundColor Red
    } else {
        Write-Host "OK: klyuch otsutstvuet v faile shifrotexta (KEY-3)" -ForegroundColor Green
    }
}

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 4. CLI-4: decrypt BEZ --key dolzhen byt oshibkoi ===" -ForegroundColor Cyan
cryptocore --algorithm aes --mode ctr --decrypt --input gen_cipher.bin --output x.bin 2>$null
Write-Host "kod vyhoda: $LASTEXITCODE (ozhidaetsya 2)"

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 5. CLI-5: preduprezhdenie o slabom klyuche ===" -ForegroundColor Cyan

# Длину ключа генерируем программно (16 байт = ровно 32 hex-символа).
# Перехват stderr внешнего .exe напрямую в переменную через "2>&1" в
# Windows PowerShell 5.1 ненадёжен (stderr оборачивается в ErrorRecord,
# и -match по нему ведёт себя непредсказуемо) - поэтому прогоняем через
# cmd.exe с перенаправлением в файл: там гарантированно обычный текст.
function Invoke-CaptureOutput($commandLine, $outFile) {
    cmd /c "$commandLine > `"$outFile`" 2>&1" | Out-Null
    if (Test-Path $outFile) {
        return Get-Content $outFile -Raw
    }
    return ""
}

$weakZeros = "0" * 32
$cmdZeros = "cryptocore --algorithm aes --mode ecb --encrypt --key $weakZeros --input plain.txt --output x.bin"
$textZeros = Invoke-CaptureOutput $cmdZeros "warn_zeros.txt"
if ($textZeros -match "WARNING") {
    Write-Host "OK: preduprezhdenie dlya nulevogo klyucha pokazano" -ForegroundColor Green
} else {
    Write-Host "FAIL: net preduprezhdeniya dlya nulevogo klyucha" -ForegroundColor Red
    Write-Host "  (poluchennyi vyvod: $textZeros)" -ForegroundColor DarkGray
}

$weakSeq = "000102030405060708090a0b0c0d0e0f"
$cmdSeq = "cryptocore --algorithm aes --mode ecb --encrypt --key $weakSeq --input plain.txt --output x.bin"
$textSeq = Invoke-CaptureOutput $cmdSeq "warn_seq.txt"
if ($textSeq -match "WARNING") {
    Write-Host "OK: preduprezhdenie dlya posledovatelnogo klyucha pokazano" -ForegroundColor Green
} else {
    Write-Host "FAIL: net preduprezhdeniya dlya posledovatelnogo klyucha" -ForegroundColor Red
    Write-Host "  (poluchennyi vyvod: $textSeq)" -ForegroundColor DarkGray
}

$cmdNormal = "cryptocore --algorithm aes --mode ecb --encrypt --key $KEY --input plain.txt --output x.bin"
$textNormal = Invoke-CaptureOutput $cmdNormal "warn_normal.txt"
if ($textNormal -match "WARNING") {
    Write-Host "FAIL: lozhnoe preduprezhdenie dlya obychnogo klyucha" -ForegroundColor Red
} else {
    Write-Host "OK: dlya obychnogo klyucha preduprezhdeniya net" -ForegroundColor Green
}

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 6. Granichnye dliny (CTR, regressiya iz sprinta 2) ===" -ForegroundColor Cyan
foreach ($n in @(0, 1, 15, 16, 17, 100)) {
    New-RandomFile "p_$n.bin" $n
    cryptocore --algorithm aes --mode ctr --encrypt --key $KEY --input "p_$n.bin" --output "c_$n.bin"
    cryptocore --algorithm aes --mode ctr --decrypt --key $KEY --input "c_$n.bin" --output "d_$n.bin"

    if (Test-FilesEqual "p_$n.bin" "d_$n.bin") {
        Write-Host "OK: $n bait" -ForegroundColor Green
    } else {
        Write-Host "FAIL: $n bait" -ForegroundColor Red
    }
}

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 7. Yavnyi --iv pri rasshifrovke (regressiya iz sprinta 2) ===" -ForegroundColor Cyan
cryptocore --algorithm aes --mode cbc --encrypt --key $KEY --input plain.txt --output cipher.bin
$ivHex = Get-HexPrefix cipher.bin 16
Split-IvAndBody cipher.bin iv.bin body.bin
cryptocore --algorithm aes --mode cbc --decrypt --key $KEY --iv $ivHex --input body.bin --output decrypted2.txt

if (Test-FilesEqual plain.txt decrypted2.txt) {
    Write-Host "OK: yavnyi --iv" -ForegroundColor Green
} else {
    Write-Host "FAIL: yavnyi --iv" -ForegroundColor Red
}

New-RandomFile short.bin 5
cryptocore --algorithm aes --mode cbc --decrypt --key $KEY --input short.bin --output x.bin 2>$null
Write-Host "korotkii fail (IO-3): kod $LASTEXITCODE (ozhidaetsya 1)"

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 8. Interop s OpenSSL (nuzhen openssl v PATH, --key is involved) ===" -ForegroundColor Cyan
$opensslAvailable = Get-Command openssl -ErrorAction SilentlyContinue

if (-not $opensslAvailable) {
    Write-Host "OpenSSL ne naiden v PATH - propuskayu interop-testy (TEST-5)." -ForegroundColor Yellow
} else {
    foreach ($mode in @("cbc", "cfb", "ofb", "ctr")) {
        cryptocore --algorithm aes --mode $mode --encrypt --key $KEY --input plain.txt --output "cipher_$mode.bin"
        $iv = Get-HexPrefix "cipher_$mode.bin" 16
        Split-IvAndBody "cipher_$mode.bin" "iv_$mode.bin" "body_$mode.bin"

        openssl enc -aes-128-$mode -d -K $KEY -iv $iv -in "body_$mode.bin" -out "openssl_decrypted_$mode.txt"

        if (Test-FilesEqual plain.txt "openssl_decrypted_$mode.txt") {
            Write-Host "OK (nash->openssl): $mode" -ForegroundColor Green
        } else {
            Write-Host "FAIL: $mode" -ForegroundColor Red
        }
    }
}

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 9. Podgotovka dannyh dlya NIST STS (TEST-3, vypolnyaetsya vruchnuyu) ===" -ForegroundColor Cyan
Write-Host "Dlya polnotsennogo statisticheskogo audita CSPRNG zapustite:"
Write-Host '  python -c "from tests.test_csprng import prepare_nist_test_data; prepare_nist_test_data()"'
Write-Host "a zatem progonite poluchennyi nist_test_data.bin cherez NIST Statistical Test Suite."
Write-Host "Etot shag ne avtomatiziruetsya v etom skripte, t.k. trebuet vneshnego instrumenta NIST STS."

Write-Host ""
Write-Host "Gotovo." -ForegroundColor Cyan
