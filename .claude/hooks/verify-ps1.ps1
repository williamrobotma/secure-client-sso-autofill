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
if (-not $file) { $file = "$($hook.tool_response.filePath)" }
if ($file -notlike '*.ps1' -or -not (Test-Path $file)) { exit 0 }

$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $file).Path, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) {
    foreach ($e in $parseErrors) {
        [Console]::Error.WriteLine("parse error: $($e.Message) (line $($e.Extent.StartLineNumber))")
    }
    exit 2
}

# Any .ps1 change (worker, config template, hooks) re-runs the worker's
# side-effect-free unit suite; it is fast and catches cross-file breakage.
$output = & powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $repoRoot 'sso-autofill.ps1') -SelfTest 2>&1
if ($LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine(($output | Out-String))
    [Console]::Error.WriteLine('sso-autofill.ps1 -SelfTest FAILED after this edit')
    exit 2
}
exit 0
