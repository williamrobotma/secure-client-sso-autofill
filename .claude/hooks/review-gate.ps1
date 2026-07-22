#requires -Version 5.1
<#
.SYNOPSIS
    Gate `git commit` on a completed security review (the DESIGN.md wrap-up
    condition, enforced instead of remembered).

.DESCRIPTION
    Enforcement runs as git's native pre-commit hook: .githooks/pre-commit
    (wired once per clone with `git config core.hooksPath .githooks`) invokes
    this script with -CheckCommit, but only inside Claude Code's Bash env
    (CLAUDECODE=1) - a human committing from a normal terminal is ungated.

    -CheckCommit hashes the staged diff at commit time and aborts (exit 1) when
    it does not match .claude/review-stamp. Because git runs the hook against the
    real index, every content-staging commit spelling is covered - env-var
    prefixes, compounds, aliases, `cherry-pick -n` - with no command-line
    parsing.

    Protocol: git add -A -> run the security-review skill -> -Stamp -> commit.
    Any later edit changes the staged diff and invalidates the stamp.

    Caveats:
      - Partial commits (`git commit <pathspec>`) hash only the pathspec'd temp
        index, so they never match the full-tree stamp - blocked. Commit the
        whole tree.
      - Empty-diff spellings (`--amend` with a clean index or a message reword,
        `--allow-empty`) stage no diff, so the gate allows them - benign: they
        record no reviewable content change.
      - `--no-verify` skips the hook (a deliberate spelling; outside the
        forgetting-not-malice threat model).

.PARAMETER Stamp
    Write the current staged-diff hash to .claude/review-stamp (gitignored).
    Run after a security review passes, with the changes already staged.

.PARAMETER CheckCommit
    Pre-commit gate: exit 0 to allow the commit, 1 to abort it.
#>
param(
    [switch]$Stamp,
    [switch]$CheckCommit
)
$ErrorActionPreference = 'Stop'

# .claude/hooks -> repo root, independent of the caller's working directory.
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$stampPath = Join-Path $repoRoot '.claude\review-stamp'

function Get-StagedDiff {
    $diff = (& git -C $repoRoot diff --cached) -join "`n"
    # A nonzero native git exit does NOT throw under $ErrorActionPreference; an
    # empty $diff would then read as "nothing staged" and allow the commit. Throw
    # so -CheckCommit's catch blocks and -Stamp aborts instead of stamping garbage.
    if ($LASTEXITCODE -ne 0) { throw "git diff --cached failed (exit $LASTEXITCODE)" }
    return $diff
}

function Get-DiffHash {
    param([string]$Diff)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Diff))
    return [System.BitConverter]::ToString($bytes) -replace '-', ''
}

if ($Stamp) {
    Set-Content -Path $stampPath -Value (Get-DiffHash (Get-StagedDiff))
    Write-Host 'review stamp written for the current staged diff'
    return
}

# Any invocation without a mode is a no-op: the gate only acts in -Stamp or
# -CheckCommit. (Keeps a stale Bash(git *) PreToolUse call, if one lingers
# before settings.json reloads, from erroring on every git command.)
if (-not $CheckCommit) { return }

try {
    $diff = Get-StagedDiff
    if (-not $diff) { return }  # nothing staged: let git report it

    $stamped = if (Test-Path $stampPath) {
        "$(Get-Content $stampPath -TotalCount 1)".Trim()
    } else { '' }
    if ((Get-DiffHash $diff) -eq $stamped) { return }

    [Console]::Error.WriteLine(
        'Security-review gate: the staged diff has no matching review stamp ' +
        '(DESIGN.md wrap-up condition). Run the security-review skill on the ' +
        'pending changes, then: powershell -NoProfile -File ' +
        '.claude/hooks/review-gate.ps1 -Stamp')
    exit 1
} catch {
    # Fail closed: a gate that errors must abort the commit, not wave it through.
    [Console]::Error.WriteLine(
        "Security-review gate errored ($($_.Exception.Message)). Fix " +
        '.claude/hooks/review-gate.ps1, or commit from your own terminal.')
    exit 1
}
