<#
  Nemesis Agent -- Behavioral Monitoring (Sysmon) deployment, Windows.

  The Windows arm of deploy_behavioral_linux.sh. Falco does not exist on Windows;
  the behavioral observer here is Sysmon writing to its Operational Event Log, which
  the agent's sysmon_collector poller reads (agent.py _sysmon_tail). This installs
  Sysmon with an ENDPOINT config, makes the channel readable by the agent, turns
  behavioral monitoring on, and PROVES detection fires with a canary.

  WHY A SEPARATE, OPT-IN STEP (same as Linux): Sysmon is a new kernel-level monitor
  in the endpoint footprint -- a security-posture decision the operator makes per
  fleet, not something the agent installer pulls in silently.

  RUN ELEVATED. An installer is installed by an admin; every step here (Sysmon
  service, an Event Log Readers grant) needs it. The script refuses if not elevated.

    powershell -ExecutionPolicy Bypass -File deploy_behavioral_windows.ps1 `
        -SysmonPath C:\Tools\Sysmon64.exe [-AgentUser 'DOMAIN\svc-nemesis']
    powershell ... -File deploy_behavioral_windows.ps1 -Uninstall
#>
[CmdletBinding()]
param(
  [string]$SysmonPath = "",
  [string]$ConfigPath = (Join-Path $PSScriptRoot "sysmon-endpoint.xml"),
  # The account the Nemesis agent RUNS AS. Only this specific account is granted
  # channel read -- a scoped, read-only grant, NOT a blanket UAC change. Empty =>
  # detect/skip: if the agent runs elevated (SYSTEM) it can already read the channel.
  [string]$AgentUser = "",
  [string]$AgentConf = "$env:ProgramData\Nemesis\agent\nemesis_agent.conf",
  [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
function Step($m){ Write-Host "`n==> $m" }
function OK($m){   Write-Host "    [OK] $m" }
function Warn($m){ Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Fail($m){ Write-Host "    [FAIL] $m" -ForegroundColor Red; exit 1 }

$SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# -- elevation gate --
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { Fail "Run ELEVATED (an installer needs admin; UAC-filtered tokens are refused)." }

function Get-SysmonService {
    Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
}

# -- uninstall (reversible, proven) --
if ($Uninstall) {
    Step "Uninstalling behavioral monitoring (reversible)"
    $svc = Get-SysmonService
    if ($svc -and $SysmonPath -and (Test-Path $SysmonPath)) {
        & $SysmonPath -u force | Out-Null    # Sysmon -u returns 13 on success too
        Start-Sleep 2
    } elseif ($svc) {
        Warn "Sysmon service present but -SysmonPath not given; leaving Sysmon installed."
    }
    if ($AgentUser) {
        # remove ONLY our scoped grant
        cmd /c "net localgroup `"Event Log Readers`" `"$AgentUser`" /delete" 2>$null | Out-Null
        OK "removed the Event Log Readers grant for $AgentUser (if present)"
    }
    if (Test-Path $AgentConf) {
        (Get-Content $AgentConf) -replace '^behavioral_enabled\s*=.*','behavioral_enabled = false' |
            Set-Content $AgentConf
        OK "agent config: behavioral_enabled = false"
    }
    $svc2 = Get-SysmonService
    if ($svc2 -and $svc2.Status -eq 'Running') {
        Warn "Sysmon still running (pass -SysmonPath to fully remove it)."
    } else { OK "Sysmon not running (verified)" }
    OK "behavioral monitoring disabled."
    exit 0
}

# -- preflight --
Step "Preflight"
if (-not (Test-Path $ConfigPath)) { Fail "endpoint Sysmon config not found: $ConfigPath" }
OK "endpoint config: $ConfigPath"
$existing = Get-SysmonService

# -- install / update Sysmon with the ENDPOINT config --
Step "Installing/updating Sysmon with the endpoint config"
if (-not $SysmonPath -or -not (Test-Path $SysmonPath)) {
    if ($existing) { Warn "Sysmon already installed and no -SysmonPath given; will only update the config via the service." }
    else { Fail "Sysmon not installed and -SysmonPath not provided. Download Sysmon64.exe and pass -SysmonPath." }
}
# 2>&1 captures Sysmon's own output so a native stderr does NOT trip
# ErrorActionPreference=Stop into an empty exception (that exact bug bit the first
# run). Sysmon returns rc 13 ON SUCCESS, so the exit code is not the signal; the
# service state and the ACTIVE-config readback below are.
# Capture Sysmon output via CMD redirection to a file, NOT PowerShell's 2>&1.
# PowerShell wraps a native command's stderr as ERROR RECORDS, so Out-String then
# renders PowerShell's own 'NativeCommandError' text instead of Sysmon's real
# message (and trips Stop). cmd '> file 2>&1' captures the actual bytes Sysmon
# wrote. Judge on the SERVICE + the active-config readback, never the exit code
# (Sysmon returns 13 on success).
$applyLog = Join-Path $env:TEMP "nemesis_sysmon_apply.txt"
$liveLog  = Join-Path $env:TEMP "nemesis_sysmon_live.txt"
if ($existing) {
    if (-not $SysmonPath) { Fail "cannot update config without -SysmonPath" }
    cmd /c "`"$SysmonPath`" -nologo -c `"$ConfigPath`" > `"$applyLog`" 2>&1" | Out-Null
} else {
    cmd /c "`"$SysmonPath`" -accepteula -nologo -i `"$ConfigPath`" > `"$applyLog`" 2>&1" | Out-Null
    Start-Sleep 3
}
$out = (Get-Content $applyLog -Raw -ErrorAction SilentlyContinue)
if ($out) { Write-Host "    sysmon: $(($out -replace '\s+',' ').Trim())" }
$svc = Get-SysmonService
if (-not $svc -or $svc.Status -ne 'Running') {
    Fail "Sysmon service is not Running after install. Sysmon reported: $out"
}
OK "Sysmon service Running: $($svc.Name)"

# VERIFY the endpoint config ACTUALLY WENT LIVE. A rejected config leaves the
# PREVIOUS one running, so 'service Running' alone is a false pass. Dump Sysmon's
# ACTIVE config and confirm one of OUR RuleNames is in it -- the real proof.
cmd /c "`"$SysmonPath`" -nologo -c > `"$liveLog`" 2>&1" | Out-Null
$live = (Get-Content $liveLog -Raw -ErrorAction SilentlyContinue)
if ($live -notmatch 'LSASS Access') {
    Fail "endpoint config did NOT go live (Sysmon still on a different config). Apply output: $out"
}
OK "endpoint config is LIVE (verified by reading Sysmon's active config back)"

try { $null = Get-WinEvent -ListLog $SYSMON_CHANNEL -ErrorAction Stop; OK "Sysmon Operational channel present" }
catch { Fail "Sysmon Operational channel not present after install: $($_.Exception.Message)" }

# -- channel read access for the agent (SCOPED, read-only) --
Step "Ensuring the agent can READ the Sysmon channel"
if (-not $AgentUser) {
    Warn "No -AgentUser given. If the agent runs as SYSTEM/elevated (schtasks /RL HIGHEST) it can already read the channel and no grant is needed. If it runs as a normal account, re-run with -AgentUser '<account>' to grant a SCOPED, read-only Event Log Readers membership."
} elseif ($AgentUser -match '^(NT AUTHORITY\\SYSTEM|SYSTEM|LocalSystem)$') {
    OK "agent runs as SYSTEM -- already reads the channel; no grant needed."
} else {
    # ONE scoped, read-only grant of the SPECIFIC agent account. NOT a blanket
    # UAC/token-policy change, NOT a user-triggerable elevated task.
    cmd /c "net localgroup `"Event Log Readers`" `"$AgentUser`" /add" 2>&1 | Out-Null
    $members = cmd /c "net localgroup `"Event Log Readers`""
    if ($members -match [regex]::Escape($AgentUser.Split('\')[-1])) {
        OK "granted $AgentUser read access via Event Log Readers (scoped, read-only)"
        Warn "the agent process must RE-LOGON to pick up the new group (group membership is baked into the token at logon) -- restart the agent service after this."
    } else {
        Warn "could not confirm the Event Log Readers grant for $AgentUser; verify manually."
    }
}

# -- CANARY: prove detection actually fires AND is readable --
Step "CANARY -- proving detection reaches the channel"
# a benign but rule-matching trigger: an -EncodedCommand PowerShell run matches the
# 'Suspicious Process Creation' rule (CommandLine contains -EncodedCommand). The
# payload is a harmless 'exit'. "Deployed" must mean detection works, not "service
# started" -- same discipline as the Linux canary.
$before = 0
try { $before = (Get-WinEvent -LogName $SYSMON_CHANNEL -MaxEvents 1 -ErrorAction Stop).RecordId } catch {}
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("exit 0"))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-EncodedCommand",$enc -WindowStyle Hidden -Wait
Start-Sleep 3
$hit = $false
try {
    $evs = Get-WinEvent -FilterHashtable @{LogName=$SYSMON_CHANNEL; Id=1} -MaxEvents 40 -ErrorAction SilentlyContinue
    foreach ($e in $evs) { if ($e.Message -match 'RuleName.*Suspicious Process Creation' -or $e.Message -match 'EncodedCommand') { $hit = $true; break } }
} catch { Fail "cannot read the Sysmon channel back for the canary: $($_.Exception.Message)" }
if (-not $hit) {
    Fail "CANARY FAILED: a known suspicious process-create did not surface in the Sysmon channel. Detection is NOT working; refusing to report success."
}
OK "canary event observed in the Sysmon channel -- detection chain proven"

# -- enable behavioral in the agent config --
Step "Enabling behavioral monitoring in the agent config"
if (Test-Path $AgentConf) {
    $c = Get-Content $AgentConf
    if ($c -match '^behavioral_enabled\s*=') { $c = $c -replace '^behavioral_enabled\s*=.*','behavioral_enabled = true' }
    else { $c += 'behavioral_enabled = true' }
    $c | Set-Content $AgentConf
    OK "agent config updated (behavioral_enabled = true)"
    $agentSvc = Get-Service -Name nemesis-agent -ErrorAction SilentlyContinue
    if ($agentSvc) { Restart-Service nemesis-agent -ErrorAction SilentlyContinue; OK "nemesis-agent restarted (fresh token, picks up any grant + the enabled flag)" }
    else { Warn "nemesis-agent service not found -- set behavioral_enabled=true and restart the agent so it re-logons for the channel grant." }
} else {
    Warn "agent config $AgentConf not found -- install the agent, then set behavioral_enabled = true and restart it."
}

Write-Host ""
OK "Behavioral monitoring DEPLOYED and PROVEN (Sysmon endpoint config + channel access + canary)."
Write-Host "    Uninstall (reversible):  powershell -File $PSCommandPath -Uninstall -SysmonPath <path> -AgentUser <acct>"
