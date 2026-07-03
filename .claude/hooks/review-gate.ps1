#requires -Version 5.1
<#
.SYNOPSIS
    Gate `git commit` on a completed security review (the DESIGN.md wrap-up
    condition, enforced instead of remembered).

.DESCRIPTION
    Hook mode (default): reads the PreToolUse JSON from stdin. If the Bash
    command contains a `git commit`, compares the staged-diff hash against
    .claude/review-stamp and denies the tool call when they differ or no stamp
    exists. Non-commit commands and an empty index pass through untouched.

    Protocol: git add -A -> run the security-review skill -> stamp -> commit.

.PARAMETER Stamp
    Write the current staged-diff hash to .claude/review-stamp (gitignored).
    Run after a security review passes, with the changes already staged.
#>
param([switch]$Stamp)
$ErrorActionPreference = 'Stop'

# .claude/hooks -> repo root, independent of the hook's working directory.
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$stampPath = Join-Path $repoRoot '.claude\review-stamp'

function Get-StagedDiffHash {
    # -Stamp calls with no arg (capture here); the gate passes the diff it
    # already captured for the emptiness check, so `git diff --cached` runs
    # once per gated commit rather than twice.
    param([string]$Diff)
    if (-not $PSBoundParameters.ContainsKey('Diff')) {
        $Diff = (& git -C $repoRoot diff --cached) -join "`n"
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Diff))
    return [System.BitConverter]::ToString($hash) -replace '-', ''
}

function Deny {
    param([string]$Reason)
    @{ hookSpecificOutput = @{
        hookEventName            = 'PreToolUse'
        permissionDecision       = 'deny'
        permissionDecisionReason = $Reason
    } } | ConvertTo-Json -Compress
    exit 0
}

if ($Stamp) {
    Set-Content -Path $stampPath -Value (Get-StagedDiffHash)
    Write-Host 'review stamp written for the current staged diff'
    return
}

try {
    $hook = [Console]::In.ReadToEnd() | ConvertFrom-Json
    # Split compound commands; anchor per part so quoted text ("git commit") in
    # some other command does not trip the gate.
    $parts = "$($hook.tool_input.command)" -split '&&|\|\||;|\||\r?\n'
    $isCommit = $false
    foreach ($p in $parts) {
        if ($p -match '^\s*git(\.exe)?\s.*\bcommit\b') { $isCommit = $true }
    }
    if (-not $isCommit) { exit 0 }

    # The stamp vouches for the staged diff ONLY. Anything unstaged or untracked
    # could still reach this commit (-a/--all, pathspec forms, a git add earlier
    # in the same compound), so require a fully staged worktree before the hash
    # compare. Staged-only lines ('M ', 'A ', ...) are fine; '??' and a dirty
    # worktree column are not.
    $notStaged = @(& git -C $repoRoot status --porcelain) |
        Where-Object { $_ -match '^\?\?' -or $_[1] -ne ' ' }
    if ($notStaged) {
        Deny ('Security-review gate: unstaged/untracked changes present, and the ' +
            'review stamp only covers the staged diff. git add -A in its own ' +
            'command, re-run the security review, re-stamp, then commit.')
    }
    $stagedDiff = (& git -C $repoRoot diff --cached) -join "`n"
    if (-not $stagedDiff) { exit 0 }  # nothing to commit: let git report it

    $stamped = if (Test-Path $stampPath) { "$(Get-Content $stampPath -TotalCount 1)".Trim() } else { '' }
    if ((Get-StagedDiffHash -Diff $stagedDiff) -eq $stamped) { exit 0 }

    Deny ('Security-review gate: the staged diff has no matching review stamp ' +
        '(DESIGN.md wrap-up condition). Run the security-review skill on the ' +
        'pending changes, then: powershell -NoProfile -File .claude/hooks/review-gate.ps1 -Stamp')
} catch {
    # Fail closed: a gate that errors must not wave commits through.
    Deny ("Security-review gate errored ($($_.Exception.Message)). Fix " +
        '.claude/hooks/review-gate.ps1 (or commit from your own terminal).')
}
