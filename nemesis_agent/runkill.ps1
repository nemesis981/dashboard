# L2 validation kit -- runkill.ps1  (agent-independent kill switch)
# Verifies the kill switch (sc stop WinDivert + taskkill) restores traffic on a HUNG L2
# process. Uses a long stall timeout so the watchdog does NOT fire in-window -- the kill
# switch is what recovers it. Note (proven): on a hung process, 'sc stop' parks at
# STOP_PENDING (filter still held) until the taskkill frees the handle; after both, the
# driver reaches STOPPED and traffic restores. Transcript -> kill_transcript.txt.
# Usage:  powershell -ExecutionPolicy Bypass -File runkill.ps1 [stall_seconds]
# Prereq: run in a dir holding l2_windivert.py + config.py; Admin.
param([int]$Stall = 40)
$ErrorActionPreference = "Continue"
$dir = "$env:USERPROFILE\l2test"; Set-Location $dir
# Long watchdog timeout so the WATCHDOG does NOT fire during this test -- the kill
# switch must be what restores traffic (proves it is agent-independent).
"[nemesis]`r`nl2_stall_timeout_sec = $Stall" | Out-File -Encoding ascii "$dir\nemesis_agent.conf"

function Test-TcpQuick($h, $port, $timeoutMs) {
  $c = New-Object Net.Sockets.TcpClient
  try {
    $iar = $c.BeginConnect($h, $port, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne($timeoutMs)) { $c.EndConnect($iar); return $true }
    return $false
  } catch { return $false } finally { $c.Close() }
}

$secs = ($Stall * 4) + 5
$log = "$dir\out_kill.log"; $err = "$dir\out_kill.err"
Remove-Item $log, $err -ErrorAction SilentlyContinue
Start-Transcript -Path "$dir\kill_transcript.txt" -Force | Out-Null

Write-Host "=== KILLSWITCH TEST: hang stall=${Stall}s (watchdog will NOT fire in-window)  $(Get-Date -Format o) ==="
$p = Start-Process python -ArgumentList "l2_windivert.py --simulate-hang $secs" `
     -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -NoNewWindow
Write-Host "test agent (python) PID=$($p.Id)"

Start-Sleep 3
$o1 = Test-TcpQuick "1.1.1.1" 443 3000
Write-Host ("during-hang, BEFORE kill switch: outbound succeeded={0}  {1}" -f $o1, (Get-Date -Format o))
Write-Host ("WinDivert state before: " + ((sc.exe query WinDivert | Select-String 'STATE') -replace '\s+',' '))

Write-Host "--- KILL SWITCH: sc stop WinDivert  $(Get-Date -Format o) ---"
sc.exe stop WinDivert
Start-Sleep 2
Write-Host ("WinDivert state after:  " + ((sc.exe query WinDivert | Select-String 'STATE') -replace '\s+',' '))
$o2 = Test-TcpQuick "1.1.1.1" 443 3000
Write-Host ("after kill switch:               outbound succeeded={0}  {1}" -f $o2, (Get-Date -Format o))

Write-Host "--- taskkill the hung test agent (PID=$($p.Id)) ---"
taskkill /F /PID $p.Id 2>&1 | Out-Host
Start-Sleep 1
$alive = [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)
Write-Host "test agent still alive after taskkill: $alive"

Write-Host "=== KILL STDOUT ==="; if (Test-Path $log) { Get-Content $log }
Write-Host "=== KILL LOG (note: no L2 STALL line; watchdog never fired, kill switch recovered it) ==="; if (Test-Path $err) { Get-Content $err }
Write-Host "=== END KILLSWITCH ==="
Stop-Transcript | Out-Null
