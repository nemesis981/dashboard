<#
  Nemesis Agent -- privileged IPC service (Windows), step 3b deployment.

  Registers the SYSTEM-privileged service (LocalSystem) that hosts the
  authenticated named-pipe channel, records the enrolled agent-user SID the
  service locks the pipe to, starts it under the SCM, and PROVES the
  authenticated round-trip with a canary. In 3b the service does NOTHING
  privileged -- it answers a `ping`. 3c adds memory inspection on this proven channel.

  WHY A REAL SERVICE (not a scheduled task): the privileged component needs to
  start at boot and be SCM-managed, and 3c needs a real service regardless -- so it
  is built correctly once here (privservice.py + winsvc.py implement the SCM
  dispatch in pure ctypes, no pywin32).

  ENCODING: this file MUST stay pure ASCII (no em dashes, no box-drawing).
  Windows PowerShell 5.1 reads a BOM-less .ps1 as the ANSI codepage, so a UTF-8 em
  dash arrives as U+201D -- which PowerShell treats as a real string delimiter. One
  of them inside a quoted string closes it early and the whole file fails to parse.
  Verified live 2026-08-22: this script would not parse at all on a stock Windows 11
  box until it was made ASCII-only. test_ps1_encoding.py enforces this.

  RUN ELEVATED.
    powershell -ExecutionPolicy Bypass -File deploy_privservice_windows.ps1 `
        -InstallDir C:\nemesis-agent [-AgentUser DOMAIN\user] [-PythonExe C:\...\python.exe]
    powershell ... -File deploy_privservice_windows.ps1 -Uninstall
#>
[CmdletBinding()]
param(
  [string]$InstallDir = "C:\nemesis-agent",
  [string]$AgentUser  = "",                 # defaults to the current user
  [string]$PythonExe  = "python",
  [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$SvcName  = "nemesis-agent-priv"
$RegPath  = "HKLM:\SOFTWARE\Nemesis\PrivChannel"

function Step($m){ Write-Host "`n==> $m" }
function OK($m){   Write-Host "    [OK] $m" }
function Warn($m){ Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Fail($m){ Write-Host "    [FAIL] $m" -ForegroundColor Red; exit 1 }

# -- elevation gate --
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { Fail "Run ELEVATED (service create + HKLM write need admin)." }

function Resolve-Sid([string]$account) {
    try { return ([System.Security.Principal.NTAccount]$account).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $null }
}

# -- uninstall (reversible, proven) --
if ($Uninstall) {
    Step "Removing the privileged IPC service (reversible)"
    if (Get-Service -Name $SvcName -ErrorAction SilentlyContinue) {
        & sc.exe stop $SvcName | Out-Null
        Start-Sleep 2
        & sc.exe delete $SvcName | Out-Null
        OK "service $SvcName stopped and deleted"
    } else { Warn "service $SvcName not present" }
    if (Test-Path $RegPath) { Remove-Item $RegPath -Recurse -Force; OK "removed $RegPath" }
    $svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if (-not $svc) { OK "verified: service gone" } else { Warn "service still present" }
    OK "privileged IPC service disabled."
    exit 0
}

# -- preflight --
Step "Preflight"
$svcScript = Join-Path $InstallDir "privservice.py"
if (-not (Test-Path $svcScript)) { Fail "privservice.py not found in $InstallDir" }
OK "service script: $svcScript"
if (-not $AgentUser) { $AgentUser = "$env:USERDOMAIN\$env:USERNAME" }
$AgentSid = Resolve-Sid $AgentUser
if (-not $AgentSid) { Fail "could not resolve a SID for agent user '$AgentUser'" }
if ($AgentSid -eq "S-1-5-18") { Fail "agent user resolves to LocalSystem -- that is the server identity, not the client." }
OK "agent user: $AgentUser  (SID $AgentSid)"

# -- record the agent-user SID the service locks the pipe to (HKLM, admin-only) --
Step "Recording the enrolled agent-user SID"
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
Set-ItemProperty -Path $RegPath -Name "AgentUserSid" -Value $AgentSid
OK "HKLM\SOFTWARE\Nemesis\PrivChannel\AgentUserSid = $AgentSid"

# -- create the LocalSystem service --
Step "Creating the SYSTEM service $SvcName"
# Resolve python to an absolute path so the SCM (which has no PATH of the user)
# can launch it.
$pyResolved = (Get-Command $PythonExe -ErrorAction SilentlyContinue).Source
if (-not $pyResolved) { $pyResolved = $PythonExe }
$binPath = "`"$pyResolved`" `"$svcScript`""
if (Get-Service -Name $SvcName -ErrorAction SilentlyContinue) {
    & sc.exe stop $SvcName | Out-Null; Start-Sleep 1; & sc.exe delete $SvcName | Out-Null; Start-Sleep 1
}
# sc.exe is picky: a SPACE is required after each '=' option.
& sc.exe create $SvcName binPath= "$binPath" obj= "LocalSystem" start= "auto" type= "own" DisplayName= "Nemesis Privileged Agent" | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "sc create failed (exit $LASTEXITCODE)" }
# Auto-restart on crash (reset the count daily; restart after 5s, three times).
& sc.exe failure $SvcName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
OK "service created (LocalSystem, start=auto, auto-restart on failure)"

Step "Starting the service"
& sc.exe start $SvcName | Out-Null
Start-Sleep 3
$svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Fail "service is not Running after start (state=$($svc.Status)). Check the agent log / Event Log."
}
OK "service is Running"

# -- CANARY: prove the AUTHENTICATED round-trip, not just 'the service started' --
Step "CANARY -- proving an authenticated ping round-trips to a verified-SYSTEM server"
# privclient.ping() verifies the server is LocalSystem before sending, and the
# server authorizes this caller's SID against the recorded agent-user SID. Run it
# from THIS session. An elevated token keeps the same USER SID, so when the deploy
# user IS the agent user (the common case), the ACL authorizes it and we get pong.
$canaryPy  = Join-Path $env:TEMP "nemesis-privcanary.py"
$canaryOut = Join-Path $env:TEMP "nemesis-privcanary.out"
@"
import sys, json
sys.path.insert(0, r'$InstallDir')
import privclient
try:
    print('CANARY_RESULT ' + json.dumps(privclient.ping()))
except Exception as e:
    print('CANARY_ERROR ' + type(e).__name__ + ': ' + str(e))
"@ | Set-Content -Path $canaryPy -Encoding UTF8

# Deliberately NOT `& $pyResolved -c $py 2>&1 | Out-String`.
# With $ErrorActionPreference = "Stop" (set at the top of this script), PowerShell
# wraps ANY native stderr output as its own NativeCommandError, which trips Stop and
# TERMINATES the script. The canary's whole job is to report a failure clearly, so a
# construct that dies on the failure path instead of reporting it is exactly backwards
# -- a Python traceback would have killed the deploy with an unrelated-looking
# PowerShell error rather than printing CANARY_ERROR. Redirect inside cmd, then read
# the file back; nothing reaches PowerShell's native-stderr handling at all.
& cmd /c "`"$pyResolved`" `"$canaryPy`" > `"$canaryOut`" 2>&1"
$out = ""
if (Test-Path $canaryOut) { $out = (Get-Content $canaryOut -Raw) }
Remove-Item $canaryPy, $canaryOut -Force -ErrorAction SilentlyContinue
if (-not $out -or -not $out.Trim()) {
    Fail "CANARY produced NO output at all - the round-trip could not be measured, so the channel is UNPROVEN. Refusing to report success."
}
Write-Host "    $($out.Trim())"
if ($out -match 'CANARY_RESULT.*"pong":\s*true') {
    OK "authenticated ping round-trip PROVEN (verified-SYSTEM server, agent-user authorized)"
} elseif ($out -match 'PrivChannelAuthError') {
    Warn "the channel is up, but this deploy context is not the agent user, so the canary could not authenticate. Run the agent (as $AgentUser) to confirm end-to-end."
} else {
    Fail "CANARY FAILED: no authenticated pong. The service is Running but the channel did not round-trip. Refusing to report success."
}

Write-Host ""
OK "Privileged IPC service DEPLOYED (LocalSystem service + locked pipe + SID auth)."
Write-Host "    Uninstall (reversible):  powershell -File $PSCommandPath -Uninstall"
