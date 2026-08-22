#Requires -RunAsAdministrator
#
# ENCODING: this file MUST stay pure ASCII (no em dashes, no box-drawing).
# Windows PowerShell 5.1 reads a BOM-less .ps1 as the ANSI codepage, so a UTF-8 em
# dash arrives as U+201D -- which PowerShell treats as a real string delimiter. One
# of them inside a quoted string closes it early and the whole file fails to parse.
# Every line of this banner carries its own '#': an un-prefixed block placed outside
# the <# #> delimiters PARSES CLEANLY as bareword commands and only fails at RUNTIME.
# test_ps1_encoding.py enforces both the encoding and this banner's commenting.
#

<#
    Nemesis Agent -- Windows uninstaller.

    Removes the Nemesis agent cleanly: scheduled tasks, running processes, the
    install directory, and our own Windows Defender exclusion. Best-effort tells
    the server the device is gone.

    What it NEVER touches:
      - Tailscale (the user's own software, not ours)
      - Any user files outside %APPDATA%\Nemesis
      - Any Windows setting beyond our own Defender exclusion

    Run elevated:  powershell -ExecutionPolicy Bypass -File uninstall_windows.ps1
#>

$ErrorActionPreference = "SilentlyContinue"

$InstallDir = Join-Path $env:APPDATA "Nemesis"
$ConfPath   = Join-Path $InstallDir "nemesis_agent.conf"

function Remove-NemesisTask {
    param([string]$Name)
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask  -TaskName $Name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "  OK Removed: scheduled task '$Name'" -ForegroundColor Green
    } else {
        Write-Host "  -  Not present: scheduled task '$Name'" -ForegroundColor DarkGray
    }
}

function Stop-NemesisProcess {
    param([string]$Name)   # process name without .exe
    $procs = Get-Process -Name $Name -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "  OK Stopped: process '$Name'" -ForegroundColor Green
    } else {
        Write-Host "  -  Not running: process '$Name'" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "Uninstalling Nemesis Agent..." -ForegroundColor Cyan
Write-Host ""

# 1. Scheduled tasks (NemesisAgent + NemesisLHM are real; NemesisFreshclam best-effort).
Remove-NemesisTask "NemesisAgent"
Remove-NemesisTask "NemesisLHM"
Remove-NemesisTask "NemesisFreshclam"

# 2. Running processes.
Stop-NemesisProcess "NemesisAgent"
Stop-NemesisProcess "LibreHardwareMonitor"

# 3. Best-effort: tell the server this device is being removed (non-blocking).
if (Test-Path $ConfPath) {
    try {
        $conf = @{}
        Get-Content $ConfPath | ForEach-Object {
            if ($_ -match '^\s*([^=#\s]+)\s*=\s*(.+?)\s*$') { $conf[$Matches[1]] = $Matches[2] }
        }
        $ip   = $conf["nemesis_ip"]
        $port = $conf["nemesis_port"]; if (-not $port) { $port = "5001" }
        $did  = $conf["device_id"]
        $pub  = ""
        $pubPath = Join-Path $InstallDir "keys\public.pem"
        if (Test-Path $pubPath) { $pub = (Get-Content $pubPath -Raw) }
        if ($ip -and $did) {
            $body = @{ source = "nemesis_agent"; device_id = $did; public_key = $pub } | ConvertTo-Json
            Invoke-RestMethod -Method Post -Uri "http://${ip}:${port}/api/agent/uninstall" `
                              -Body $body -ContentType "application/json" -TimeoutSec 8 | Out-Null
            Write-Host "  OK Notified server (device marked uninstalled)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  -  Could not reach server (removed locally anyway)" -ForegroundColor DarkGray
    }
}

# 4. Remove our own Windows Defender exclusion (only ours).
try {
    Remove-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Write-Host "  OK Removed: Windows Defender exclusion" -ForegroundColor Green
} catch {
    Write-Host "  -  No Defender exclusion to remove" -ForegroundColor DarkGray
}

# 5. Remove the install directory entirely (NemesisAgent.exe, clamav\, lhm\,
#    keys\, nemesis_agent.conf, yara_rules\ -- everything under %APPDATA%\Nemesis).
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) {
        Write-Host "  !  Some files could not be removed (in use?): $InstallDir" -ForegroundColor Yellow
    } else {
        Write-Host "  OK Removed: $InstallDir" -ForegroundColor Green
    }
} else {
    Write-Host "  -  Install directory already gone" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Nemesis Agent uninstalled successfully." -ForegroundColor Green
Write-Host "Tailscale was not removed - uninstall it separately if needed from" -ForegroundColor Yellow
Write-Host "Settings > Apps." -ForegroundColor Yellow
Write-Host ""
