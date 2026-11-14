# One-click HashCam. Double-click HashCam.bat; nothing to type.
#
#   HashCam.bat                 starts the test database (if it is not running), the recorder, the
#                               console and the website; copies the extension's pairing token to the
#                               clipboard; opens the website and the console in your browser.
#   HashCam-Stop.bat            stops the recorder, console and website (also any left over from an
#                               earlier run). The test database is left running.
#   HashCam-Extension-Setup.bat the one-time, click-only steps to add the extension to Chrome.
#
# Everything runs on this computer only (127.0.0.1). The services run hidden; their logs are in
# %LOCALAPPDATA%\HashCam\logs. The pairing token is never printed: it goes to the clipboard.
param(
    [switch]$Stop,
    [switch]$ExtensionSetup,
    [switch]$NoOpen,   # do not open browser windows or Explorer (used by the tests)
    [switch]$Quiet,    # print to the console instead of showing message boxes; leave the clipboard alone
    [int]$WebsitePort = 8000,
    [int]$ConsolePort = 8765,
    [int]$RecorderPort = 8770,
    [string]$DataDir = (Join-Path $env:USERPROFILE ".hashcam"),
    [string]$StateDir = (Join-Path $env:LOCALAPPDATA "HashCam")
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms

$repo = Split-Path -Parent $PSScriptRoot
$work = Join-Path $env:LOCALAPPDATA "Temp\claude"
$logs = Join-Path $StateDir "logs"
$pidFile = Join-Path $StateDir "pids.txt"
$tokenFile = Join-Path $DataDir "recorder-token"
$viewerFile = Join-Path $DataDir "recorder-viewer-key"
$databasePort = 55432
New-Item -ItemType Directory -Force $logs | Out-Null

function Say([string]$text, [string]$icon = "Information") {
    if ($Quiet) { Write-Host $text; return }
    [void][System.Windows.Forms.MessageBox]::Show($text, "HashCam", "OK", $icon)
}

function Test-Port([int]$port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect("127.0.0.1", $port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(400)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch { return $false } finally { $client.Close() }
}

function Wait-Port([int]$port, [int]$seconds) {
    $end = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $end) {
        if (Test-Port $port) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function First-Existing([string[]]$candidates) {
    foreach ($c in $candidates) { if ($c -and (Test-Path $c)) { return $c } }
    return $null
}

# Is the recorder on this port one the console and extension can actually use (right token, the
# current API)? A recorder left running from an earlier version answers differently.
function Test-Recorder([int]$port) {
    if (-not (Test-Path $tokenFile)) { return $false }
    try {
        $token = (Get-Content $tokenFile -Raw).Trim()
        $answer = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$port/sessions" -Headers @{ "X-HashCam-Token" = $token } -TimeoutSec 8
        return ($answer.StatusCode -eq 200)
    } catch { return $false }
}

# ------------------------------------------------------------------ stop

if ($Stop) {
    $stopped = New-Object System.Collections.ArrayList
    if (Test-Path $pidFile) {
        foreach ($line in Get-Content $pidFile) {
            $id = 0
            if ([int]::TryParse($line.Trim(), [ref]$id) -and $id -gt 0) {
                if (Get-Process -Id $id -ErrorAction SilentlyContinue) {
                    # /T ends the whole tree: the recorder starts the signer and the ledger API as children.
                    & taskkill /PID $id /T /F 2>$null | Out-Null
                    [void]$stopped.Add("service $id")
                }
            }
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
    # Anything HashCam left listening on these ports (from an earlier run) is stopped too.
    $names = @{ $WebsitePort = "website"; $ConsolePort = "console"; $RecorderPort = "recorder" }
    foreach ($port in $names.Keys) {
        $owners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($id in $owners) {
            $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue).CommandLine
            if ($cmd -match 'recorder\.py|ui_server\.py|http\.server') {
                & taskkill /PID $id /T /F 2>$null | Out-Null
                [void]$stopped.Add($names[$port])
            }
        }
    }
    Start-Sleep -Milliseconds 800
    $still = @($names.Keys | Where-Object { Test-Port $_ })
    $message = if ($stopped.Count -gt 0) { "Stopped $($stopped.Count) HashCam process(es)." } else { "Nothing of HashCam was running." }
    if ($still.Count -gt 0) { $message += "`nPort(s) still in use by something else: " + ($still -join ", ") }
    Say ($message + "`nThe test database, if it was started, is left running.")
    exit 0
}

# ------------------------------------------------------------------ one-time extension setup

function Find-Browser {
    return First-Existing @(
        (Join-Path $env:ProgramFiles "Google\Chrome\Application\chrome.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Google\Chrome\Application\chrome.exe"),
        (Join-Path $env:LOCALAPPDATA "Google\Chrome\Application\chrome.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft\Edge\Application\msedge.exe")
    )
}

if ($ExtensionSetup) {
    $folder = Join-Path $repo "extension"
    $browser = Find-Browser
    if (-not $NoOpen) {
        if ($browser) {
            $page = if ($browser -like "*msedge.exe") { "edge://extensions" } else { "chrome://extensions" }
            Start-Process -FilePath $browser -ArgumentList $page
        }
        Start-Process explorer.exe -ArgumentList ('"' + $folder + '"')
    }
    Say ("One time only, and only clicks:`n`n" +
        "1. In the page that just opened (Extensions), turn on Developer mode (top right).`n" +
        "2. Click Load unpacked.`n" +
        "3. Pick this folder:`n   $folder`n" +
        "4. Click the puzzle-piece icon in the toolbar, pin HashCam, and click its icon.`n" +
        "5. Paste the pairing token (HashCam.bat puts it on your clipboard) and register your passkey.`n`n" +
        "Press Ctrl+C on this box to copy the folder path.")
    exit 0
}

# ------------------------------------------------------------------ start

$report = New-Object System.Collections.ArrayList
$problems = New-Object System.Collections.ArrayList

try {
    $py = First-Existing @((Join-Path $work "abbvenv\Scripts\python.exe"))
    if (-not $py) {
        $found = Get-Command python -ErrorAction SilentlyContinue
        if ($found) { $py = $found.Source }
    }
    if (-not $py) { throw "Python was not found. Install Python 3.11 or newer, then run this again." }

    $abb = First-Existing @($env:ABB_BIN, (Join-Path $work "abbt\debug\abb.exe"), (Join-Path $work "abbt\release\abb.exe"))
    $signer = First-Existing @($env:ABB_SIGNER_BIN, (Join-Path $work "abbt\debug\abb-signer.exe"), (Join-Path $work "abbt\release\abb-signer.exe"))
    $dsn = "postgresql://abb@127.0.0.1:$databasePort/postgres"
    if ($abb) { $env:ABB_BIN = $abb }
    if ($signer) { $env:ABB_SIGNER_BIN = $signer }
    $env:ABB_TEST_DSN = $dsn
    $env:PYTHONUNBUFFERED = "1"
    $receipts = Join-Path $DataDir "receipts"
    New-Item -ItemType Directory -Force $receipts | Out-Null

    # 1. The test database the recorder needs (only if it is not already answering).
    $pgctl = First-Existing @((Join-Path $env:ProgramFiles "PostgreSQL\18\bin\pg_ctl.exe"), (Join-Path $env:ProgramFiles "PostgreSQL\17\bin\pg_ctl.exe"), (Join-Path $env:ProgramFiles "PostgreSQL\16\bin\pg_ctl.exe"))
    $pgdata = First-Existing @((Join-Path $work "pgdata"))
    if (-not (Test-Port $databasePort)) {
        if ($pgctl -and $pgdata) {
            & $pgctl -D $pgdata -l (Join-Path $logs "postgres.log") -o "-p $databasePort -c autovacuum=off -c max_connections=200" start 2>&1 | Out-Null
            [void](Wait-Port $databasePort 40)
        }
    }
    $dbUp = Test-Port $databasePort

    function Start-Piece([string]$name, [int]$port, [string]$arguments, [int]$waitSeconds) {
        if (Test-Port $port) { return "running" }
        $out = Join-Path $logs "$name.out.log"
        $err = Join-Path $logs "$name.err.log"
        $p = Start-Process -FilePath $py -ArgumentList $arguments -WorkingDirectory $repo -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
        Add-Content -Path $pidFile -Value $p.Id
        if (Wait-Port $port $waitSeconds) { return "started" }
        [void]$problems.Add("$name did not start. Its log: $err")
        return "failed"
    }

    # 2. The website: the public site, served from this folder.
    $web = Start-Piece "Website" $WebsitePort ("-m http.server $WebsitePort --bind 127.0.0.1 --directory `"$(Join-Path $repo 'site')`"") 20
    [void]$report.Add("Website: $web (port $WebsitePort)")

    # 3. The recorder (needs the verifier program, the signer and the database).
    $recorderOk = $false
    if ($abb -and $signer -and $dbUp) {
        $recorderArgs = "`"$(Join-Path $repo 'tools\recorder.py')`" --dsn $dsn --port $RecorderPort --allow-site http://127.0.0.1:$WebsitePort" +
            " --token-file `"$tokenFile`" --viewer-key-file `"$viewerFile`" --receipts `"$receipts`" --people-dir `"$(Join-Path $DataDir 'people')`""
        $state = Start-Piece "Recorder" $RecorderPort $recorderArgs 90
        if ($state -eq "running") {
            if (Test-Recorder $RecorderPort) { $recorderOk = $true }
            else {
                [void]$problems.Add("A recorder is already running on port $RecorderPort but HashCam cannot use it (it is probably left over from an earlier version). Double-click HashCam-Stop.bat, then HashCam.bat again.")
            }
        } elseif ($state -eq "started") { $recorderOk = $true }
        [void]$report.Add("Recorder: $state (port $RecorderPort)")
    } else {
        $missing = @()
        if (-not $abb) { $missing += "the verifier program (abb.exe)" }
        if (-not $signer) { $missing += "the signer (abb-signer.exe)" }
        if (-not $dbUp) { $missing += "the test database (PostgreSQL on port $databasePort)" }
        [void]$problems.Add("The recorder was not started because " + ($missing -join ", ") + " could not be found.")
    }

    # 4. The console (it reads the recorder's token itself; nothing to paste).
    $consoleArgs = "`"$(Join-Path $repo 'tools\ui_server.py')`" --receipts `"$receipts`" --port $ConsolePort" +
        " --recorder http://127.0.0.1:$RecorderPort --recorder-token-file `"$tokenFile`""
    if ($abb) { $consoleArgs += " --abb `"$abb`"" }
    $console = Start-Piece "Console" $ConsolePort $consoleArgs 40
    [void]$report.Add("Console: $console (port $ConsolePort)")

    # 5. The extension's pairing token goes to the clipboard, never to the screen.
    $copied = $false
    if ($recorderOk) {
        for ($i = 0; $i -lt 20 -and -not (Test-Path $tokenFile); $i++) { Start-Sleep -Milliseconds 300 }
        if (Test-Path $tokenFile) {
            if (-not $Quiet) { Set-Clipboard -Value ((Get-Content $tokenFile -Raw).Trim()); $copied = $true }
        }
    }

    if (-not $NoOpen) {
        if (Test-Port $WebsitePort) { Start-Process "http://127.0.0.1:$WebsitePort/" }
        if (Test-Port $ConsolePort) { Start-Process "http://127.0.0.1:$ConsolePort/console" }
    }

    $text = "HashCam is running (on this computer only):`n`n" + ($report -join "`n")
    $text += "`n`nWebsite: http://127.0.0.1:$WebsitePort/`nConsole: http://127.0.0.1:$ConsolePort/console"
    if ($copied) { $text += "`n`nThe extension's pairing token is on your clipboard: open the HashCam icon in Chrome and paste it once." }
    $text += "`nFirst time? Run HashCam-Extension-Setup.bat."
    $text += "`nTo stop everything: HashCam-Stop.bat."
    if ($problems.Count -gt 0) { $text += "`n`nPlease note:`n" + ($problems -join "`n") }
    Say $text $(if ($problems.Count -gt 0) { "Warning" } else { "Information" })
} catch {
    Say ("HashCam could not start.`n`n" + $_.Exception.Message + "`n`nLogs: $logs") "Error"
    exit 1
}
