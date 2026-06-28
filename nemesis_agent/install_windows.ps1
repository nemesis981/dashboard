# Nemesis Agent — Windows Installer
# Run as Administrator: powershell -ExecutionPolicy Bypass -File install_windows.ps1

#Requires -RunAsAdministrator
param(
    [string]$NemesisIP = "",
    [string]$DeviceName = ""
)

$InstallDir = "C:\nemesis-agent"
$TaskName   = "NemesisAgent"

function Write-Step { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "    [!!] $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "    [FAIL] $msg" -ForegroundColor Red }

# ── 1. Visual C++ Redistributable ────────────────────────────────────────────
Write-Step "Checking Visual C++ Redistributable 2015-2022..."
$vcKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
$vcInstalled = (Test-Path $vcKey) -and ((Get-ItemProperty $vcKey -ErrorAction SilentlyContinue).Installed -eq 1)
if (-not $vcInstalled) {
    Write-Warn "Visual C++ Redistributable not found — downloading and installing..."
    $vcUrl  = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    $vcFile = "$env:TEMP\vc_redist.x64.exe"
    Invoke-WebRequest -Uri $vcUrl -OutFile $vcFile -UseBasicParsing
    Start-Process -FilePath $vcFile -ArgumentList "/install /quiet /norestart" -Wait
    Write-OK "Visual C++ Redistributable installed"
} else {
    Write-OK "Visual C++ Redistributable already present"
}

# ── 2. Python ─────────────────────────────────────────────────────────────────
Write-Step "Checking Python 3.8+..."
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Warn "Python not found."
    Write-Host "    Please download and install Python 3.8+ from https://www.python.org/downloads/windows/"
    Write-Host "    IMPORTANT: Check 'Add Python to PATH' during installation."
    Write-Host "    After installing Python, re-run this script."
    Read-Host "Press Enter when Python is installed"
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Write-Fail "Python still not found — aborting"
        exit 1
    }
}
$pyver = & python --version 2>&1
Write-OK "Found: $pyver"

# ── 3. Pip packages ──────────────────────────────────────────────────────────
Write-Step "Installing Python packages..."
& python -m pip install --upgrade pip --quiet
& python -m pip install requests psutil watchdog plyer pywin32 cryptography --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Fail "pip install failed — ensure Visual C++ Redistributable is installed first"
    exit 1
}
Write-OK "Python packages installed"

# ── 3b. Tailscale (remote access for the road) ───────────────────────────────
Write-Step "Checking Tailscale (remote access to your Nemesis box)..."
$ts = Get-Command tailscale -ErrorAction SilentlyContinue
if (-not $ts) {
    $resp = Read-Host "Tailscale not found. Install it now? (recommended for remote/road use) [y/N]"
    if ($resp -eq 'y' -or $resp -eq 'Y') {
        winget install Tailscale.Tailscale --silent --accept-package-agreements --accept-source-agreements
        Write-OK "Tailscale installed — run 'tailscale up' and sign in to join your tailnet"
    } else {
        Write-Warn "Skipped Tailscale — the Nemesis box must be reachable on your LAN/VPN"
    }
} else {
    Write-OK "Tailscale already installed"
}

# ── 3c. LibreHardwareMonitor web server (temps/fans on port 8085) ─────────────
Write-Step "Starting LibreHardwareMonitor web server (port 8085)..."
$lhmExe = "C:\Program Files\LibreHardwareMonitor\LibreHardwareMonitor.exe"
if (Test-Path $lhmExe) {
    Start-Process -FilePath $lhmExe -WindowStyle Minimized -ErrorAction SilentlyContinue
    Write-OK "LibreHardwareMonitor started (enable Options -> Web Server if not already on)"
} else {
    Write-Warn "LibreHardwareMonitor not found at $lhmExe"
    Write-Host "    Temps/fans need LHM: https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases"
    Write-Host "    Then enable Options -> Web Server (port 8085). The agent still runs without it (psutil only)."
}

# ── 4. Copy agent files ──────────────────────────────────────────────────────
Write-Step "Installing agent to $InstallDir..."
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item -Path "$ScriptDir\*" -Destination $InstallDir -Recurse -Force
Write-OK "Files copied to $InstallDir"

# ── 5. Configure nemesis_agent.conf ─────────────────────────────────────────
Write-Step "Configuring agent..."
$confPath = "$InstallDir\nemesis_agent.conf"
if (-not (Test-Path $confPath)) {
    $confTemplate = @"
[nemesis]
nemesis_ip = REPLACE_ME
nemesis_port = 5001
nemesis_subnet =
device_name = My Windows PC
device_id =
poll_interval = 300
suricata_enabled = false
suricata_profile = auto
scan_on_reconnect = true
last_scan_at =
"@
    $confTemplate | Out-File -FilePath $confPath -Encoding utf8
}

if ($NemesisIP) {
    (Get-Content $confPath) -replace "nemesis_ip = REPLACE_ME", "nemesis_ip = $NemesisIP" | Set-Content $confPath
}
if ($DeviceName) {
    (Get-Content $confPath) -replace "device_name = My Windows PC", "device_name = $DeviceName" | Set-Content $confPath
}

if ((Get-Content $confPath) -match "REPLACE_ME") {
    $ip = Read-Host "Enter your Nemesis server address (Tailscale IP or LAN IP)"
    (Get-Content $confPath) -replace "REPLACE_ME", $ip | Set-Content $confPath
}

$dn = Read-Host "Enter a friendly name for this device (e.g. 'Paul's Laptop') [press Enter to keep current]"
if ($dn) {
    (Get-Content $confPath) -replace "device_name = .*", "device_name = $dn" | Set-Content $confPath
}
Write-OK "Configuration saved"

# ── 6. Windows Defender exclusion ────────────────────────────────────────────
Write-Step "Adding Windows Defender exclusion for $InstallDir..."
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction Stop
    Write-OK "Exclusion added"
} catch {
    Write-Warn "Could not add Defender exclusion (non-fatal): $_"
}

# ── 7. Task Scheduler ────────────────────────────────────────────────────────
Write-Step "Creating Task Scheduler task '$TaskName'..."
$action  = New-ScheduledTaskAction -Execute "python" -Argument "$InstallDir\agent.py" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit 0
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal | Out-Null
    Write-OK "Scheduled task created (runs at logon)"
} catch {
    Write-Warn "Task Scheduler failed (non-fatal): $_"
}

# ── 8. Start agent ────────────────────────────────────────────────────────────
Write-Step "Starting Nemesis Agent..."
Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  Nemesis Agent installed successfully!" -ForegroundColor Green
Write-Host "  Install dir: $InstallDir" -ForegroundColor Green
Write-Host "  Log file:    $InstallDir\nemesis_agent.log" -ForegroundColor Green
Write-Host "  Config:      $InstallDir\nemesis_agent.conf" -ForegroundColor Green
Write-Host "" -ForegroundColor Green
Write-Host "  NEXT STEP — approve this device:" -ForegroundColor Yellow
Write-Host "    The agent generated a keypair and requested enrollment." -ForegroundColor Yellow
Write-Host "    Open your Nemesis dashboard -> Settings -> Devices and click" -ForegroundColor Yellow
Write-Host "    Approve. The agent will start reporting once approved." -ForegroundColor Yellow
Write-Host "============================================================`n" -ForegroundColor Green
