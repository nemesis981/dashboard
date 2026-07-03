# L2 validation kit -- runhang.ps1  (stall-watchdog)
# Drives l2_windivert.py --simulate-hang to verify the stall-watchdog force-closes the
# handle and restores traffic. Probes outbound during the hang (blocked) and after the
# watchdog fires (restored), and prints the "L2 STALL ... force-closing" log line + result.
# Usage:  powershell -ExecutionPolicy Bypass -File runhang.ps1 [stall_seconds]
# Prereq: run in a dir holding l2_windivert.py + config.py; Admin (WinDivert driver load).
param([int]$Stall = 5)
$ErrorActionPreference = "Continue"
$dir = "$env:USERPROFILE\l2test"; Set-Location $dir
"[nemesis]`r`nl2_stall_timeout_sec = $Stall" | Out-File -Encoding ascii "$dir\nemesis_agent.conf"

function Test-TcpQuick($h, $port, $timeoutMs) {
  $c = New-Object Net.Sockets.TcpClient
  try {
    $iar = $c.BeginConnect($h, $port, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne($timeoutMs)) { $c.EndConnect($iar); return $true }
    return $false
  } catch { return $false } finally { $c.Close() }
}

$secs = [Math]::Max(($Stall * 4) + 5, 25)
$log = "$dir\out_hang.log"; $err = "$dir\out_hang.err"
Remove-Item $log, $err -ErrorAction SilentlyContinue

Write-Host "=== HANG START stall=${Stall}s harness=${secs}s  $(Get-Date -Format o) ==="
$p = Start-Process python -ArgumentList "l2_windivert.py --simulate-hang $secs" `
     -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -NoNewWindow

Start-Sleep -Seconds 2
$r1 = Test-TcpQuick "1.1.1.1" 443 3000
Write-Host ("OUTBOUND during-hang  (t+2s, 3s timeout): succeeded={0}  {1}" -f $r1, (Get-Date -Format o))

Start-Sleep -Seconds ($Stall + 4)
$r2 = Test-TcpQuick "1.1.1.1" 443 3000
Write-Host ("OUTBOUND post-recovery (t+$($Stall+6)s):        succeeded={0}  {1}" -f $r2, (Get-Date -Format o))

$p.WaitForExit()
Write-Host "=== HANG STDOUT ==="; if (Test-Path $log) { Get-Content $log }
Write-Host "=== HANG LOG ==="; if (Test-Path $err) { Get-Content $err }
Write-Host "=== END HANG ==="
