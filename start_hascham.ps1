# Starts Hascham: asks for your TinyFish key, starts the test database if needed,
# starts the server and opens the page. The key is typed hidden, kept only in this
# window's memory, and never written to a file or printed.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$work = Join-Path $env:LOCALAPPDATA "Temp\claude"
$python = Join-Path $work "abbvenv\Scripts\python.exe"
$pgctl = "C:\Program Files\PostgreSQL\18\bin\pg_ctl.exe"
$pgdata = Join-Path $work "pgdata"
$runs = Join-Path $work "runs"
$port = 8767

if (-not (Test-Path $python)) { Write-Host "Cannot find the Python environment at $python" -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }
New-Item -ItemType Directory -Force $runs | Out-Null

# 1. The key, typed hidden. Leave empty to browse old runs without starting new ones.
$secure = Read-Host "Paste your TinyFish key (hidden; press Enter to skip and only view runs)" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
if ($plain) { $env:TINYFISH_API_KEY = $plain } else { Remove-Item Env:TINYFISH_API_KEY -ErrorAction SilentlyContinue }
$plain = $null

# 1b. An older copy of this server on the same port would keep serving old code. Stop it.
$old = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($old) {
    Write-Host "Stopping the older Hascham server on port $port..."
    $old | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 1
}

# 2. The test database on port 55432.
function Test-Db { (Test-NetConnection 127.0.0.1 -Port 55432 -WarningAction SilentlyContinue).TcpTestSucceeded }
if (-not (Test-Db)) {
    Write-Host "Starting the test database..."
    & $pgctl -D $pgdata -l (Join-Path $work "pg.log") -o "-p 55432 -c autovacuum=off -c max_connections=200" start | Out-Null
    Start-Sleep -Seconds 4
}
if (-not (Test-Db)) { Write-Host "The test database did not start. Tell Claude." -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }

# 3. Paths the server needs.
$env:PYTHONPATH = "."
$env:ABB_TEST_DSN = "postgresql://abb@127.0.0.1:55432/postgres"
$env:ABB_BIN = Join-Path $work "abbt\debug\abb.exe"
$env:ABB_SIGNER_BIN = Join-Path $work "abbt\debug\abb-signer.exe"
# The Real website mode drives a Chromium that is already downloaded here.
$browsers = Join-Path $work "pw-browsers"
if (Test-Path $browsers) { $env:PLAYWRIGHT_BROWSERS_PATH = $browsers }

# 4. Open the page a moment after the server starts, then run the server (Ctrl+C stops it).
Start-Job -ScriptBlock { Start-Sleep -Seconds 3; Start-Process "http://127.0.0.1:$using:port/run" } | Out-Null
Write-Host ""
Write-Host "Hascham is starting at http://127.0.0.1:$port/run  (Ctrl+C to stop)" -ForegroundColor Green
& $python tools/ui_server.py --receipts $runs --enable-runs --port $port
