#requires -Version 5.1
<#
.SYNOPSIS
    PostToolUse hook: after an Edit/Write to a .ps1 file, parse-check it and
    run the worker's -SelfTest. Exit 2 feeds the failure back to Claude.
#>
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$hook = [Console]::In.ReadToEnd() | ConvertFrom-Json
$file = "$($hook.tool_input.file_path)"
if ($file -notlike '*.ps1' -or -not (Test-Path -LiteralPath $file)) { exit 0 }

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $file).Path, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) {
    foreach ($e in $parseErrors) {
        [Console]::Error.WriteLine("parse error: $($e.Message) (line $($e.Extent.StartLineNumber))")
    }
    exit 2
}

# Any .ps1 change (worker, config template, hooks) re-runs the worker's
# side-effect-free unit suite (SendKeys escaping, window matcher, and the
# config.example.ps1 <-> required-names contract) - fast, and it catches the
# config-template drift that would otherwise surface only at a live run.
#
# EAP is relaxed around the child call: a failing -SelfTest throws in the child,
# whose stderr would otherwise promote to a terminating NativeCommandError here
# (this hook runs under EAP=Stop) and kill the hook with exit 1 - but PostToolUse
# only feeds exit 2 back to Claude. Relaxing EAP lets the full 2>&1 output land
# in $output so the exit code, not the stderr write, decides.
$eap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$output = & powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $repoRoot 'sso-autofill.ps1') -SelfTest 2>&1
$selfTestExit = $LASTEXITCODE
$ErrorActionPreference = $eap
if ($selfTestExit -ne 0) {
    [Console]::Error.WriteLine(($output | Out-String))
    [Console]::Error.WriteLine('sso-autofill.ps1 -SelfTest FAILED after this edit')
    exit 2
}

# op-guard (PreToolUse secret-print guard) has its own side-effect-free suite;
# run it too so a broken guard is caught at edit time, same as the worker.
$opGuard = Join-Path $repoRoot '.claude\hooks\op-guard.ps1'
if (Test-Path -LiteralPath $opGuard) {
    $ErrorActionPreference = 'Continue'
    $guardOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $opGuard -SelfTest 2>&1
    $guardExit = $LASTEXITCODE
    $ErrorActionPreference = $eap
    if ($guardExit -ne 0) {
        [Console]::Error.WriteLine(($guardOut | Out-String))
        [Console]::Error.WriteLine('op-guard.ps1 -SelfTest FAILED after this edit')
        exit 2
    }
}
exit 0
