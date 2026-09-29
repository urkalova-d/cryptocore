# ======================================================================
# Скрипт проверки CryptoCore. Запускать целиком: .\test_all.ps1
# (файл сохранён в UTF-8 с BOM — так Windows PowerShell 5.1 корректно
# распознаёт кодировку и не портит русский текст в строках)
# ======================================================================

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

$KEY = "000102030405060708090a0b0c0d0e0f"
Set-Content -Path plain.txt -Value "Testovoe soobschenie dlya proverki CryptoCore." -NoNewline

Write-Host ""
Write-Host "=== 1. Avtotesty ===" -ForegroundColor Cyan
python -m tests.test_roundtrip
python -m tests.test_modes

Write-Host ""
Write-Host "=== 2. Round-trip po rezhimam ===" -ForegroundColor Cyan
foreach ($mode in @("ecb", "cbc", "cfb", "ofb", "ctr")) {
    cryptocore --algorithm aes --mode $mode --encrypt --key $KEY --input plain.txt --output "cipher_$mode.bin"
    cryptocore --algorithm aes --mode $mode --decrypt --key $KEY --input "cipher_$mode.bin" --output "decrypted_$mode.txt"

    if (Test-FilesEqual plain.txt "decrypted_$mode.txt") {
        Write-Host "OK: $mode" -ForegroundColor Green
    } else {
        Write-Host "FAIL: $mode" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== 3. Granichnye dliny (CTR) ===" -ForegroundColor Cyan
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

Write-Host ""
Write-Host "=== 4. Yavnyi --iv pri rasshifrovke ===" -ForegroundColor Cyan
cryptocore --algorithm aes --mode cbc --encrypt --key $KEY --input plain.txt --output cipher.bin
$ivHex = Get-HexPrefix cipher.bin 16
Split-IvAndBody cipher.bin iv.bin body.bin
cryptocore --algorithm aes --mode cbc --decrypt --key $KEY --iv $ivHex --input body.bin --output decrypted2.txt

if (Test-FilesEqual plain.txt decrypted2.txt) {
    Write-Host "OK: yavnyi --iv" -ForegroundColor Green
} else {
    Write-Host "FAIL: yavnyi --iv" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== 5. Obrabotka oshibok (sveryaem kody vyhoda) ===" -ForegroundColor Cyan

cryptocore --algorithm aes --mode ecb --encrypt --key zz --input plain.txt --output x.bin 2>$null
Write-Host "nevernyi --key: kod $LASTEXITCODE (ozhidaetsya 2)"

cryptocore --algorithm aes --mode cbc --encrypt --key $KEY --iv $ivHex --input plain.txt --output x.bin 2>$null
Write-Host "--iv pri encrypt: kod $LASTEXITCODE (ozhidaetsya 2)"

cryptocore --algorithm aes --mode ecb --decrypt --key $KEY --iv $ivHex --input cipher.bin --output x.bin 2>$null
Write-Host "--iv dlya ecb: kod $LASTEXITCODE (ozhidaetsya 2)"

cryptocore --algorithm aes --mode ecb --encrypt --key $KEY --input nofile.txt --output x.bin 2>$null
Write-Host "nesuschestvuyuschii fail: kod $LASTEXITCODE (ozhidaetsya 1)"

New-RandomFile short.bin 5
cryptocore --algorithm aes --mode cbc --decrypt --key $KEY --input short.bin --output x.bin 2>$null
Write-Host "korotkii fail: kod $LASTEXITCODE (ozhidaetsya 1)"

Write-Host ""
Write-Host "=== 6. Interop s OpenSSL (nuzhen openssl v PATH) ===" -ForegroundColor Cyan
$opensslAvailable = Get-Command openssl -ErrorAction SilentlyContinue

if (-not $opensslAvailable) {
    Write-Host "OpenSSL ne naiden v PATH - propuskayu interop-testy." -ForegroundColor Yellow
    Write-Host "Ustanovite: winget install ShiningLight.OpenSSL.Light (i otkroite novyi terminal)"
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

    $iv2 = "AABBCCDDEEFF00112233445566778899"
    foreach ($mode in @("cbc", "cfb", "ofb", "ctr")) {
        openssl enc -aes-128-$mode -K $KEY -iv $iv2 -in plain.txt -out "openssl_cipher_$mode.bin"
        cryptocore --algorithm aes --mode $mode --decrypt --key $KEY --iv $iv2 --input "openssl_cipher_$mode.bin" --output "our_decrypted_$mode.txt"

        if (Test-FilesEqual plain.txt "our_decrypted_$mode.txt") {
            Write-Host "OK (openssl->nash): $mode" -ForegroundColor Green
        } else {
            Write-Host "FAIL: $mode" -ForegroundColor Red
        }
    }

    New-RandomFile plain16.bin 32
    cryptocore --algorithm aes --mode ecb --encrypt --key $KEY --input plain16.bin --output c_ecb.bin
    openssl enc -aes-128-ecb -d -K $KEY -in c_ecb.bin -out d_ecb.bin -nopad

    if (Test-FilesEqual plain16.bin d_ecb.bin) {
        Write-Host "OK: ecb vs openssl" -ForegroundColor Green
    } else {
        Write-Host "FAIL: ecb vs openssl" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Gotovo." -ForegroundColor Cyan
