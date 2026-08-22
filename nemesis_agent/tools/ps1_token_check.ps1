# ps1_token_check.ps1 -- the AUTHORITATIVE Windows-side gate for shipped .ps1 files.
# RUN ON WINDOWS (the test VM). Not part of the agent.
#
# NOTE this header uses '#' line comments, NOT a block comment. It has to discuss
# block-comment delimiters, and a literal close-delimiter inside a block comment ENDS
# it -- which is exactly how the first version of this file failed to parse. Caught by
# running it on the VM, 2026-08-22.
#
# WHY THIS EXISTS, AND WHY A PARSE CHECK ALONE IS NOT ENOUGH (2026-08-22)
# ----------------------------------------------------------------------
# Two .ps1 defects shipped this week and each defeated the previous check:
#
#   1. install_windows.ps1 would NOT PARSE on a stock box. A BOM-less UTF-8 em dash
#      arrives as U+201D, which PowerShell treats as a real string delimiter, so one
#      em dash inside a quoted string closed it early. A parse check catches this.
#
#   2. uninstall_windows.ps1 PARSED CLEANLY WITH ZERO ERRORS while carrying a
#      five-line ENCODING banner outside its block comment with no '#' prefix. Those
#      lines are valid SYNTAX -- PowerShell tokenises "ENCODING:" as a command name
#      and the rest as its arguments -- so the parser is perfectly happy and the file
#      fails only at RUNTIME with "the term is not recognized". A parse check is
#      BLIND to this.
#
# So this tool checks two different things:
#   * zero parse errors                        (catches class 1)
#   * the ENCODING banner tokenises as Comment (catches class 2)
#
# The second uses PowerShell's own lexer rather than our guess about what counts as a
# comment -- the point of running on Windows at all is to stop inferring.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File ps1_token_check.ps1 -Path C:\ps1dir

[CmdletBinding()]
param([string]$Path = "C:\nemesis-ps")

$marker = "ENCODING: this file MUST stay pure ASCII"
$fail = 0

# This tool holds the marker as DATA (it must name the string it searches for), so it
# would flag itself. Skipping SELF specifically -- not a blanket exemption, and the
# Python-side test carries the same narrow entry with a stale-exemption guard.
$self = $MyInvocation.MyCommand.Name

Get-ChildItem -Path (Join-Path $Path "*.ps1") | Sort-Object Name | ForEach-Object {
    $file = $_
    if ($file.Name -eq $self) {
        Write-Host ("SKIP  {0}  (this checker; holds the marker as data)" -f $file.Name)
        return
    }
    $errors = $null; $tokens = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName, [ref]$tokens, [ref]$errors)

    $nerr = if ($errors) { $errors.Count } else { 0 }
    if ($nerr -gt 0) {
        Write-Host ("FAIL  {0}  ({1} parse errors)" -f $file.Name, $nerr)
        $errors | Select-Object -First 2 | ForEach-Object {
            Write-Host ("        line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) }
        $script:fail++
        return
    }

    # Banner check: every line carrying the marker, and the contiguous block after it,
    # must be covered by Comment tokens. Ask the lexer, do not pattern-match.
    $lines = Get-Content $file.FullName
    $bannerLines = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -like "*$marker*") {
            for ($j = $i; $j -lt $lines.Count; $j++) {
                if (-not $lines[$j].Trim()) { break }
                $bannerLines += ($j + 1)
            }
            break
        }
    }
    if ($bannerLines.Count -eq 0) { Write-Host ("OK    {0}" -f $file.Name); return }

    $commentLines = @{}
    $tokens | Where-Object { $_.Kind -eq "Comment" } | ForEach-Object {
        for ($l = $_.Extent.StartLineNumber; $l -le $_.Extent.EndLineNumber; $l++) {
            $commentLines[$l] = $true } }

    $bad = $bannerLines | Where-Object { -not $commentLines.ContainsKey($_) }
    if ($bad) {
        Write-Host ("FAIL  {0}  banner lines NOT tokenised as Comment: {1}" -f
                    $file.Name, ($bad -join ", "))
        # NOTE: bind the line number to its own variable. Using $_ inside the nested
        # pipeline rebinds it to the TOKEN, so the diagnostic printed empty -- an
        # instrument that reported nothing while looking like it reported something.
        $bad | Select-Object -First 3 | ForEach-Object {
            $lineNo = $_
            $kinds = ($tokens |
                      Where-Object { $_.Extent.StartLineNumber -eq $lineNo } |
                      Select-Object -First 5 |
                      ForEach-Object { $_.Kind }) -join ","
            Write-Host ("        line {0} tokenises as: {1}" -f $lineNo, $kinds) }
        $script:fail++
    } else {
        Write-Host ("OK    {0}  (banner: {1} lines, all Comment)" -f
                    $file.Name, $bannerLines.Count)
    }
}

Write-Host ""
if ($fail -gt 0) { Write-Host ("FAILED - {0} file(s)" -f $fail); exit 1 }
Write-Host "ALL PASS"
