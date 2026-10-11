
param([switch]$Large)

$script:failed = 0

function Check($name, $condition) {
    # единая точка учёта результатов: печатает OK/FAIL и считает провалы
    if ($condition) {
        Write-Host "OK: $name" -ForegroundColor Green
    } else {
        Write-Host "FAIL: $name" -ForegroundColor Red
        $script:failed = $script:failed + 1
    }
}

function Get-FirstToken($line) {
    # первое слово строки вывода dgst, то есть сам хэш
    return ($line -split '\s+')[0]
}

function New-RandomFile($path, $n) {
    # RNGCryptoServiceProvider: RandomNumberGenerator.Fill нет в PowerShell 5.1
    $bytes = New-Object byte[] $n
    if ($n -gt 0) {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($bytes)
        $rng.Dispose()
    }
    [System.IO.File]::WriteAllBytes((Join-Path (Get-Location) $path), $bytes)
}

function New-BytesFile($path, [byte[]]$bytes) {
    [System.IO.File]::WriteAllBytes((Join-Path (Get-Location) $path), $bytes)
}

# маленький Python-помощник с эталонным хэшем (одинарные кавычки внутри
# нужны, чтобы PowerShell 5.1 не терял кавычки при вызове python)
$refScript = @'
import hashlib, sys
h = hashlib.new(sys.argv[1])
with open(sys.argv[2], 'rb') as f:
    while True:
        chunk = f.read(1048576)
        if not chunk:
            break
        h.update(chunk)
print(h.hexdigest())
'@
Set-Content -Path "_ref_hash.py" -Value $refScript -Encoding ASCII

function Get-RefHash($algo, $path) {
    # $algo: sha256 или sha3_256 (имена hashlib)
    return (python _ref_hash.py $algo $path).Trim()
}

Write-Host ""
Write-Host "=== 1. Avtotesty (hash + regressiya) ===" -ForegroundColor Cyan
python -m tests.test_hash
Check "tests.test_hash" ($LASTEXITCODE -eq 0)
python -m tests.test_hash_avalanche
Check "tests.test_hash_avalanche" ($LASTEXITCODE -eq 0)
python -m tests.test_roundtrip
Check "tests.test_roundtrip" ($LASTEXITCODE -eq 0)
python -m tests.test_modes
Check "tests.test_modes" ($LASTEXITCODE -eq 0)
python -m tests.test_csprng
Check "tests.test_csprng" ($LASTEXITCODE -eq 0)

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 2. TEST-1/TEST-2: izvestnye vektory NIST i pustoi fail ===" -ForegroundColor Cyan

New-BytesFile "k_empty.bin" ([byte[]]@())
New-BytesFile "k_abc.bin" ([System.Text.Encoding]::ASCII.GetBytes("abc"))
New-BytesFile "k_448.bin" ([System.Text.Encoding]::ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
New-BytesFile "k_million.bin" ([System.Text.Encoding]::ASCII.GetBytes("a" * 1000000))

$r = Get-FirstToken (cryptocore dgst --algorithm sha256 --input k_empty.bin)
Check "sha256 pustoi fail" ($r -eq "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
$r = Get-FirstToken (cryptocore dgst --algorithm sha3-256 --input k_empty.bin)
Check "sha3-256 pustoi fail" ($r -eq "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")

$r = Get-FirstToken (cryptocore dgst --algorithm sha256 --input k_abc.bin)
Check "sha256 abc" ($r -eq "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
$r = Get-FirstToken (cryptocore dgst --algorithm sha3-256 --input k_abc.bin)
Check "sha3-256 abc" ($r -eq "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")

$r = Get-FirstToken (cryptocore dgst --algorithm sha256 --input k_448.bin)
Check "sha256 NIST 448 bit" ($r -eq "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")

Write-Host "(1 000 000 simvolov 'a' - zajmet neskolko sekund)"
$r = Get-FirstToken (cryptocore dgst --algorithm sha256 --input k_million.bin)
Check "sha256 million 'a'" ($r -eq "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")

# чтение из стандартного ввода ("--input -") через cmd, чтобы PowerShell
# не подмешивал свои переводы строк и кодировку в поток
cmd /c "type k_abc.bin | cryptocore dgst --algorithm sha256 --input -" | Out-File -Encoding ASCII stdin_out.txt
$line = (Get-Content stdin_out.txt -Raw).Trim()
Check "stdin: hash abc" ((Get-FirstToken $line) -eq "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
Check "stdin: imya '-' v vyvode" ($line.EndsWith("  -"))

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 3. TEST-3: sovpadenie s etalonom (Get-FileHash i hashlib) ===" -ForegroundColor Cyan

foreach ($n in @(0, 1, 55, 56, 63, 64, 65, 135, 136, 137, 4096, 65535, 65536, 65537, 100000)) {
    $f = "r_$n.bin"
    New-RandomFile $f $n

    $mine256 = Get-FirstToken (cryptocore dgst --algorithm sha256 --input $f)
    $sys256 = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
    Check "sha256 $n bait == Get-FileHash" ($mine256 -eq $sys256)

    $mine3 = Get-FirstToken (cryptocore dgst --algorithm sha3-256 --input $f)
    $ref3 = Get-RefHash "sha3_256" $f
    Check "sha3-256 $n bait == hashlib" ($mine3 -eq $ref3)
}

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 4. CLI-4 / IO-3: format vyvoda i --output ===" -ForegroundColor Cyan

New-RandomFile "fmt.bin" 5000
$expectedHash = (Get-FileHash "fmt.bin" -Algorithm SHA256).Hash.ToLower()
$line = cryptocore dgst --algorithm sha256 --input fmt.bin
Check "format: '<hash>  <put>' (dva probela)" ($line -eq "$expectedHash  fmt.bin")

cryptocore dgst --algorithm sha256 --input fmt.bin --output fmt_out.txt
Check "--output: kod vyhoda 0" ($LASTEXITCODE -eq 0)
$fileText = Get-Content "fmt_out.txt" -Raw
Check "--output: soderzhimoe == stdout" ($fileText -eq ($line + "`n"))

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 5. CLI-3, IO-4: oshibki (kody vyhoda) ===" -ForegroundColor Cyan

cryptocore dgst --algorithm sha256 --input no_such_file.bin 2>$null
Check "net faila: kod 1" ($LASTEXITCODE -eq 1)

cryptocore dgst --algorithm sha256 --input . 2>$null
Check "vmesto faila papka: kod 1" ($LASTEXITCODE -eq 1)

cryptocore dgst --algorithm sha256 --key 000102030405060708090a0b0c0d0e0f --input fmt.bin 2>$null
Check "dgst + --key otvergnut: kod 2" ($LASTEXITCODE -eq 2)

cryptocore dgst --algorithm sha256 --mode ecb --input fmt.bin 2>$null
Check "dgst + --mode otvergnut: kod 2" ($LASTEXITCODE -eq 2)

cryptocore dgst --algorithm sha256 --encrypt --input fmt.bin 2>$null
Check "dgst + --encrypt otvergnut: kod 2" ($LASTEXITCODE -eq 2)

cryptocore dgst --algorithm md5 --input fmt.bin 2>$null
Check "neizvestnyi algoritm: kod 2" ($LASTEXITCODE -eq 2)

cryptocore dgst --algorithm sha256 2>$null
Check "bez --input: kod 2" ($LASTEXITCODE -eq 2)

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 6. Regressiya: shifrovanie rabotaet kak prezhde ===" -ForegroundColor Cyan

$KEY = "9f2b7a1e4c6d8035f10a2e9b7c4d1685"
New-RandomFile "enc_plain.bin" 777
foreach ($mode in @("ecb", "cbc", "cfb", "ofb", "ctr")) {
    cryptocore --algorithm aes --mode $mode --encrypt --key $KEY --input enc_plain.bin --output "enc_$mode.bin"
    cryptocore --algorithm aes --mode $mode --decrypt --key $KEY --input "enc_$mode.bin" --output "dec_$mode.bin"
    $h1 = (Get-FileHash "enc_plain.bin" -Algorithm SHA256).Hash
    $h2 = (Get-FileHash "dec_$mode.bin" -Algorithm SHA256).Hash
    Check "round-trip $mode" ($h1 -eq $h2)
}

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 7. TEST-6: proizvoditelnost (informativno, 1 MB) ===" -ForegroundColor Cyan

New-RandomFile "perf_1mb.bin" 1048576
$t = Measure-Command { cryptocore dgst --algorithm sha256 --input perf_1mb.bin | Out-Null }
Write-Host ("sha256   (nash, Python):  {0:N2} s" -f $t.TotalSeconds)
$t = Measure-Command { cryptocore dgst --algorithm sha3-256 --input perf_1mb.bin | Out-Null }
Write-Host ("sha3-256 (nash, Python):  {0:N2} s" -f $t.TotalSeconds)
$t = Measure-Command { Get-FileHash perf_1mb.bin -Algorithm SHA256 | Out-Null }
Write-Host ("sha256   (Get-FileHash):  {0:N4} s" -f $t.TotalSeconds)

# ----------------------------------------------------------------------
Write-Host ""
Write-Host "=== 8. TEST-4: fail > 1 GB ===" -ForegroundColor Cyan
if (-not $Large) {
    Write-Host "Propushcheno. Chtoby zapustit: .\test_sprint4.ps1 -Large" -ForegroundColor Yellow
    Write-Host "(nuzhno ~1.1 GB na diske; chistyi Python hesiruet ~0.3 MB/s, t.e. okolo chasa)"
} else {
    $big = Join-Path (Get-Location) "big_1100mb.bin"
    Write-Host "Sozdayu fail 1100 MB..."
    $buf = New-Object byte[] 1048576
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($buf)
    $rng.Dispose()
    $fs = [System.IO.File]::Create($big)
    for ($i = 0; $i -lt 1100; $i++) {
        $fs.Write($buf, 0, $buf.Length)
    }
    $fs.Close()

    Write-Host "Schitayu sha256 nashim instrumentom (dolgo)..."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $mineBig = Get-FirstToken (cryptocore dgst --algorithm sha256 --input $big)
    $sw.Stop()
    $sysBig = (Get-FileHash $big -Algorithm SHA256).Hash.ToLower()
    Write-Host ("vremya: {0:N0} s" -f $sw.Elapsed.TotalSeconds)
    Check "sha256 fail 1100 MB == Get-FileHash" ($mineBig -eq $sysBig)
    Remove-Item $big
}

# ----------------------------------------------------------------------
# уборка временных файлов теста
Remove-Item -ErrorAction SilentlyContinue _ref_hash.py, stdin_out.txt, k_*.bin, r_*.bin, fmt.bin, fmt_out.txt, enc_*.bin, dec_*.bin, perf_1mb.bin

Write-Host ""
if ($script:failed -eq 0) {
    Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
} else {
    Write-Host ("FAILED CHECKS: {0}" -f $script:failed) -ForegroundColor Red
}
