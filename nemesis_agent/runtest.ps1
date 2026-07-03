# L2 validation kit -- runtest.ps1  (normal / crash paths)
# Drives nemesis_agent/l2_windivert.py self-test on a Windows host with pydivert installed,
# generates live outbound connections during the window, and prints the harness result +
# agent log lines. Confirms: normal traffic passes with the filter active; an injected
# per-packet crash is caught + reinjected (fail-open), traffic keeps flowing.
# Usage:  powershell -ExecutionPolicy Bypass -File runtest.ps1 <normal|crash> [secs] [stall]
# Prereq: run in a dir holding l2_windivert.py + config.py (+ reputation_cache.py); Admin.
param([string]$Mode = "normal", [int]$Secs = 25, [int]$Stall = 5, [int]$TrafficAt = 3)
$ErrorActionPreference = "Continue"
$dir = "$env:USERPROFILE\l2test"
Set-Location $dir

# Map a bare keyword to the harness flag (avoids PowerShell eating a leading "--").
switch ($Mode) {
  "normal" { $Flag = "--test-normal" }
  "crash"  { $Flag = "--simulate-crash" }
  "hang"   { $Flag = "--simulate-hang" }
  default  { $Flag = "--test-normal" }
}

# Control the watchdog stall timeout via the REAL config mechanism (script-dir conf).
"[nemesis]`r`nl2_stall_timeout_sec = $Stall" | Out-File -Encoding ascii "$dir\nemesis_agent.conf"

$tag = $Mode
$log = "$dir\out_$tag.log"
$err = "$dir\out_$tag.err"
Remove-Item $log,$err -ErrorAction SilentlyContinue

Write-Host "=== START mode=$Mode flag=$Flag secs=$Secs stall=$Stall  $(Get-Date -Format o) ==="
$p = Start-Process -FilePath "python" -ArgumentList "l2_windivert.py $Flag $Secs" `
     -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -NoNewWindow

Start-Sleep -Seconds $TrafficAt
Write-Host "--- generating outbound connections (t+${TrafficAt}s) $(Get-Date -Format o) ---"
foreach ($t in @("1.1.1.1","8.8.8.8","9.9.9.9")) {
  $r = Test-NetConnection -ComputerName $t -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
  Write-Host ("outbound {0}:443 -> succeeded={1}  {2}" -f $t, $r, (Get-Date -Format o))
}

$p.WaitForExit()
Write-Host "--- python exited code=$($p.ExitCode)  $(Get-Date -Format o) ---"
Write-Host "=== TEST STDOUT ($tag) ==="; if (Test-Path $log) { Get-Content $log }
Write-Host "=== TEST LOG/STDERR ($tag) ==="; if (Test-Path $err) { Get-Content $err }
Write-Host "=== END $tag ==="
