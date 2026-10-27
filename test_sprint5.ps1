# ======================================================================
# Проверка CryptoCore, спринт 5 (HMAC, AES-CMAC, dgst --hmac / --cmac / --verify).
# Запуск:            .\test_sprint5.ps1
# С большим файлом:  .\test_sprint5.ps1 -Large            (TEST-7, файл 1100 МиБ, очень долго)
#                    .\test_sprint5.ps1 -Large -LargeMb 50  (свой размер в МиБ)
# Файл сохранён в UTF-8 с BOM (нужно для Windows PowerShell 5.1);
# выводимые строки намеренно написаны латиницей, чтобы не зависеть от кодовой
# страницы консоли. Эталоны: hmac/hashlib из стандартной библиотеки Python.
# ======================================================================
param([switch]$Large, [int]$LargeMb = 1100)

$script:failed = 0
$key16 = "00112233445566778899aabbccddeeff"

function Check($name, $condition) {
    # единая точка учёта результатов: печатает OK/FAIL и считает провалы
    if ($condition) {
        Write-Host "OK: $name" -ForegroundColor Green
    } else {
        Write-Host "FAIL: $name" -ForegroundColor Red
        $script:failed = $script:failed + 1
    }
}

function New-BytesFile($path, [byte[]]$bytes) {
    [System.IO.File]::WriteAllBytes((Join-Path (Get-Location) $path), $bytes)
}

function New-RandomFile($path, $n) {
    # RNGCryptoServiceProvider: RandomNumberGenerator.Fill нет в PowerShell 5.1
    $bytes = New-Object byte[] $n
    if ($n -gt 0) {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($bytes)
        $rng.Dispose()
    }
    New-BytesFile $path $bytes
}

function Get-FirstToken($line) {
    return ($line -split '\s+')[0]
}

# Python-помощник с эталонным HMAC (читает файл порциями, как и сама утилита)
$refScript = @'
import hmac, sys
mac = hmac.new(bytes.fromhex(sys.argv[2]), digestmod=sys.argv[1])
with open(sys.argv[3], 'rb') as f:
    while True:
        chunk = f.read(1048576)
        if not chunk:
            break
        mac.update(chunk)
print(mac.hexdigest())
'@
Set-Content -Path "_ref_hmac.py" -Value $refScript -Encoding ASCII

function Get-RefHmac($algo, $keyHex, $path) {
    # $algo: sha256 или sha3_256 (имена hashlib)
    return (python _ref_hmac.py $algo $keyHex $path).Trim()
}

function Invoke-Dgst($argLine, $outFile) {
    # вывод и stdout, и stderr уходит в файл через cmd (в PowerShell 5.1 так надёжнее);
    # возвращается код завершения утилиты
    cmd /c "python -m src.main dgst $argLine > $outFile 2>&1"
    return $LASTEXITCODE
}

Write-Host ""
Write-Host "=== 1. Avtotesty (MAC + regressiya) ===" -ForegroundColor Cyan
python -m tests.test_hmac_vectors
Check "tests.test_hmac_vectors (RFC 4231, kliuchi, hashlib)" ($LASTEXITCODE -eq 0)
python -m tests.test_cmac
Check "tests.test_cmac (NIST SP 800-38B)" ($LASTEXITCODE -eq 0)
python -m tests.test_mac_cli
Check "tests.test_mac_cli (CLI)" ($LASTEXITCODE -eq 0)
python -m tests.test_hash
Check "tests.test_hash" ($LASTEXITCODE -eq 0)
python -m tests.test_roundtrip
Check "tests.test_roundtrip" ($LASTEXITCODE -eq 0)
python -m tests.test_modes
Check "tests.test_modes" ($LASTEXITCODE -eq 0)
python -m tests.test_csprng
Check "tests.test_csprng" ($LASTEXITCODE -eq 0)

Write-Host ""
Write-Host "=== 2. TEST-1: RFC 4231 cherez CLI ===" -ForegroundColor Cyan
[System.IO.File]::WriteAllBytes((Join-Path (Get-Location) "rfc1.txt"), [System.Text.Encoding]::ASCII.GetBytes("Hi There"))
$code = Invoke-Dgst "--algorithm sha256 --hmac --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --input rfc1.txt" "o1.txt"
Check "RFC 4231 case 1, kod 0" ($code -eq 0)
Check "RFC 4231 case 1, znachenie" ((Get-FirstToken (Get-Content o1.txt -Raw)) -eq "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
[System.IO.File]::WriteAllBytes((Join-Path (Get-Location) "rfc2.txt"), [System.Text.Encoding]::ASCII.GetBytes("what do ya want for nothing?"))
$code = Invoke-Dgst "--algorithm sha256 --hmac --key 4a656665 --input rfc2.txt" "o2.txt"
Check "RFC 4231 case 2 (Jefe)" ((Get-FirstToken (Get-Content o2.txt -Raw)) -eq "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

Write-Host ""
Write-Host "=== 3. TEST-2: generaciya i proverka (--verify) ===" -ForegroundColor Cyan
[System.IO.File]::WriteAllBytes((Join-Path (Get-Location) "file.txt"), [System.Text.Encoding]::ASCII.GetBytes("original content`n"))
$code = Invoke-Dgst "--algorithm sha256 --hmac --key $key16 --input file.txt --output original_hmac.txt" "o3.txt"
Check "--output s HMAC, kod 0" ($code -eq 0)
$line = (Get-Content original_hmac.txt -Raw).Trim()
Check "format fayla: HMAC i imya fayla" ($line -match '^[0-9a-f]{64}\s+file\.txt$')
$code = Invoke-Dgst "--algorithm sha256 --hmac --key $key16 --input file.txt --verify original_hmac.txt" "o4.txt"
Check "verify uspeshen, kod 0" ($code -eq 0)
Check "soobshchenie [OK]" ((Get-Content o4.txt -Raw) -match '\[OK\]')

Write-Host ""
Write-Host "=== 4. TEST-3: izmenenie fayla ===" -ForegroundColor Cyan
$b = [System.IO.File]::ReadAllBytes((Join-Path (Get-Location) "file.txt"))
$b[0] = $b[0] -bxor 1
New-BytesFile "file.txt" $b
$code = Invoke-Dgst "--algorithm sha256 --hmac --key $key16 --input file.txt --verify original_hmac.txt" "o5.txt"
Check "izmenennyi fayl: kod 1" ($code -eq 1)
Check "soobshchenie [ERROR]" ((Get-Content o5.txt -Raw) -match '\[ERROR\] HMAC verification failed')

Write-Host ""
Write-Host "=== 5. TEST-4: drugoi kliuch ===" -ForegroundColor Cyan
$b[0] = $b[0] -bxor 1      # возвращаем файл в исходное состояние
New-BytesFile "file.txt" $b
$code = Invoke-Dgst "--algorithm sha256 --hmac --key ff112233445566778899aabbccddeeff --input file.txt --verify original_hmac.txt" "o6.txt"
Check "drugoi kliuch: kod 1" ($code -eq 1)
$code = Invoke-Dgst "--algorithm sha256 --hmac --key $key16 --input file.txt --verify original_hmac.txt" "o7.txt"
Check "iskhodnyi kliuch i fayl: snova uspekh" ($code -eq 0)

Write-Host ""
Write-Host "=== 6. TEST-5: razmery kliuchei (sverka s hmac iz Python) ===" -ForegroundColor Cyan
New-RandomFile "msg.bin" 1000
foreach ($n in 1, 16, 63, 64, 65, 100, 200) {
    $k = -join ((1..$n) | ForEach-Object { "{0:x2}" -f (Get-Random -Minimum 0 -Maximum 256) })
    $code = Invoke-Dgst "--algorithm sha256 --hmac --key $k --input msg.bin" "ok.txt"
    Check "kliuch $n bait (sha256)" (((Get-FirstToken (Get-Content ok.txt -Raw)) -eq (Get-RefHmac "sha256" $k "msg.bin")) -and ($code -eq 0))
}
$k = -join ((1..150) | ForEach-Object { "{0:x2}" -f (Get-Random -Minimum 0 -Maximum 256) })
$code = Invoke-Dgst "--algorithm sha3-256 --hmac --key $k --input msg.bin" "ok.txt"
Check "HMAC-SHA3-256, kliuch 150 bait" ((Get-FirstToken (Get-Content ok.txt -Raw)) -eq (Get-RefHmac "sha3_256" $k "msg.bin"))

Write-Host ""
Write-Host "=== 7. TEST-6: pustoi fail ===" -ForegroundColor Cyan
New-BytesFile "empty.bin" ([byte[]]@())
$code = Invoke-Dgst "--algorithm sha256 --hmac --key $key16 --input empty.bin" "oe.txt"
Check "pustoi fail, kod 0" ($code -eq 0)
Check "pustoi fail, znachenie" ((Get-FirstToken (Get-Content oe.txt -Raw)) -eq (Get-RefHmac "sha256" $key16 "empty.bin"))

Write-Host ""
Write-Host "=== 8. TEST-7: bolshoi fail (porcii) ===" -ForegroundColor Cyan
if ($Large) {
    $mb = $LargeMb
} else {
    $mb = 3      # быстрый вариант: несколько порций по 64 КиБ; полный тест - ключ -Large
}
Write-Host "sozdayu fayl $mb MiB ..."
$fs = [System.IO.File]::Create((Join-Path (Get-Location) "large.bin"))
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$chunk = New-Object byte[] 1048576
for ($i = 0; $i -lt $mb; $i++) { $rng.GetBytes($chunk); $fs.Write($chunk, 0, $chunk.Length) }
$fs.Close(); $rng.Dispose()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$code = Invoke-Dgst "--algorithm sha256 --hmac --key $key16 --input large.bin" "ol.txt"
$sw.Stop()
Write-Host ("vremya: {0:N0} s" -f $sw.Elapsed.TotalSeconds)
Check "bolshoi fail, kod 0" ($code -eq 0)
Check "bolshoi fail, znachenie" ((Get-FirstToken (Get-Content ol.txt -Raw)) -eq (Get-RefHmac "sha256" $key16 "large.bin"))
Remove-Item large.bin -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== 9. Oshibki argumentov ===" -ForegroundColor Cyan
$code = Invoke-Dgst "--algorithm sha256 --hmac --input file.txt" "oe1.txt"
Check "--hmac bez --key: oshibka" ($code -ne 0)
$code = Invoke-Dgst "--algorithm sha256 --hmac --key abc --input file.txt" "oe2.txt"
Check "nechetnaya dlina hex: oshibka" ($code -ne 0)
$code = Invoke-Dgst "--algorithm sha256 --hmac --key zz --input file.txt" "oe3.txt"
Check "ne hex: oshibka" ($code -ne 0)
$code = Invoke-Dgst "--algorithm sha256 --key $key16 --input file.txt" "oe4.txt"
Check "--key bez --hmac: oshibka" ($code -ne 0)
Set-Content -Path "junk.txt" -Value "not a hmac" -Encoding ASCII
$code = Invoke-Dgst "--algorithm sha256 --hmac --key $key16 --input file.txt --verify junk.txt" "oe5.txt"
Check "musor v fayle s HMAC: kod 1" ($code -eq 1)
$code = Invoke-Dgst "--algorithm sha256 --hmac --key $key16 --input file.txt --verify net_takogo.txt" "oe6.txt"
Check "net fayla s HMAC: kod 1" ($code -eq 1)

Write-Host ""
Write-Host "=== 10. Bonus: AES-CMAC (NIST SP 800-38B) ===" -ForegroundColor Cyan
New-BytesFile "cmac16.bin" ([byte[]](0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a))
New-BytesFile "cmac0.bin" ([byte[]]@())
$ck = "2b7e151628aed2a6abf7158809cf4f3c"
$code = Invoke-Dgst "--cmac --key $ck --input cmac16.bin" "oc1.txt"
Check "CMAC, 16 bait" ((Get-FirstToken (Get-Content oc1.txt -Raw)) -eq "070a16b46b4d4144f79bdd9dd04a287c")
$code = Invoke-Dgst "--cmac --key $ck --input cmac0.bin" "oc2.txt"
Check "CMAC, pustoe soobshchenie" ((Get-FirstToken (Get-Content oc2.txt -Raw)) -eq "bb1d6929e95937287fa37d129b756746")
$code = Invoke-Dgst "--cmac --key $ck --input cmac16.bin --output cm.txt" "oc3.txt"
$code = Invoke-Dgst "--cmac --key $ck --input cmac16.bin --verify cm.txt" "oc4.txt"
Check "CMAC verify, kod 0" ($code -eq 0)

Write-Host ""
Write-Host "=== 11. Regressiya: obychnyi hash ne izmenilsia ===" -ForegroundColor Cyan
$code = Invoke-Dgst "--algorithm sha256 --input rfc2.txt" "or.txt"
$expected = (python -c "import hashlib;print(hashlib.sha256(b'what do ya want for nothing?').hexdigest())").Trim()
Check "dgst sha256 bez --hmac" ((Get-FirstToken (Get-Content or.txt -Raw)) -eq $expected)

# уборка временных файлов
Remove-Item _ref_hmac.py, rfc1.txt, rfc2.txt, file.txt, original_hmac.txt, msg.bin, empty.bin, junk.txt, cmac16.bin, cmac0.bin, cm.txt -ErrorAction SilentlyContinue
Remove-Item o1.txt, o2.txt, o3.txt, o4.txt, o5.txt, o6.txt, o7.txt, ok.txt, oe.txt, ol.txt, oe1.txt, oe2.txt, oe3.txt, oe4.txt, oe5.txt, oe6.txt, oc1.txt, oc2.txt, oc3.txt, oc4.txt, or.txt -ErrorAction SilentlyContinue

Write-Host ""
if ($script:failed -eq 0) {
    Write-Host "VSE PROVERKI PROSHLI" -ForegroundColor Green
    exit 0
} else {
    Write-Host "PROVALENO PROVEROK: $($script:failed)" -ForegroundColor Red
    exit 1
}
