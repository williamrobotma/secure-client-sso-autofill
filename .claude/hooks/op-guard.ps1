#Requires -Version 5.1
<#
.SYNOPSIS
  PreToolUse(Bash) guard for secure-client-sso-autofill (Windows 11-specific repo).

  Blocks any `op` (1Password CLI) invocation that would print a secret value, so the
  machine-local `op item get *` allow cannot auto-approve a secret print. Discovery
  (op item list, metadata get) falls through to normal permission handling.

  Enforced, not remembered: it matches per sub-command in any flag position, so a
  reordered flag (`op item get --otp X`) or a compound (`op item get X --reveal && cat`)
  cannot slip past the way a prefix allow rule would.

.NOTES
  Exit 0 = allow (fall through to permissions). Exit 2 = block (message -> Claude).
  Run with -SelfTest for side-effect-free test cases (used by verify hook).
#>
[CmdletBinding()]
param([switch]$SelfTest)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Secret-extraction flags (blocked in any position) and labels that name secrets.
$BlockFlags  = @('--otp', '--reveal', '--share-link')
$SecretLabel = 'password|passwd|secret|credential|token|otp|one-time|key|passphrase|pin|seed|recovery'

function Test-OpCommand {
    # Returns $null if the sub-command is allowed, or a reason string if it must be blocked.
    param([string]$Sub)
    $toks = @($Sub -split '\s+' | Where-Object { $_ -ne '' })
    if ($toks.Count -eq 0) { return $null }
    # Skip leading env-assignments (FOO=bar) and known command wrappers.
    $wrappers = @('timeout', 'time', 'nice', 'nohup', 'stdbuf', 'command', 'builtin', 'env', 'sudo')
    $i = 0
    while ($i -lt $toks.Count) {
        $t = $toks[$i]
        if ($t -match '^[A-Za-z_][A-Za-z0-9_]*=') { $i++; continue }   # env assignment
        if ($wrappers -contains $t)               { $i++; continue }   # wrapper
        break
    }
    if ($i -ge $toks.Count) { return $null }
    $cmd = [IO.Path]::GetFileNameWithoutExtension($toks[$i])           # op / op.exe -> op
    if ($cmd -ne 'op') { return $null }
    if ($i -eq $toks.Count - 1) { return $null }                       # bare `op`, no args
    $rest = @($toks[($i + 1)..($toks.Count - 1)])
    # `op read ...` fetches a single secret value directly.
    if ($rest[0] -eq 'read') { return "op read fetches a secret value directly" }
    # Blocked flags anywhere in the invocation.
    foreach ($f in $rest) {
        $bare = ($f -split '=', 2)[0]
        if ($BlockFlags -contains $bare) { return "flag '$bare' prints or reveals secrets" }
    }
    # --fields requesting a concealed field or a secret-looking label.
    for ($j = 0; $j -lt $rest.Count; $j++) {
        $f = $rest[$j]
        $val = $null
        if ($f -eq '--fields' -and $j + 1 -lt $rest.Count) { $val = $rest[$j + 1] }
        elseif ($f -like '--fields=*')                     { $val = ($f -split '=', 2)[1] }
        if ($val) {
            if ($val -match 'type=concealed')            { return "--fields type=concealed pulls secret values" }
            if ($val -match "label=[^,]*($SecretLabel)") { return "--fields requests a secret field" }
        }
    }
    return $null
}

function Test-Command {
    # Split a full Bash command into sub-commands and block if any op sub-command is unsafe.
    param([string]$Command)
    $subs = [regex]::Split($Command, '\|\||&&|\||;|&|\r?\n')
    foreach ($s in $subs) {
        $reason = Test-OpCommand $s
        if ($reason) { return $reason }
    }
    return $null
}

if ($SelfTest) {
    $cases = @(
        @{ cmd = 'op item get Google --otp';                        block = $true },
        @{ cmd = 'op item get Netflix --reveal';                    block = $true },
        @{ cmd = 'op item get --otp Google';                        block = $true },   # reordered
        @{ cmd = 'op item get X --reveal && cat /etc/passwd';       block = $true },   # compound
        @{ cmd = 'op item list --tags x | op item get - --reveal';  block = $true },   # piped chain
        @{ cmd = 'op read op://Vault/Item/password';                block = $true },
        @{ cmd = 'op item get Netflix --fields label=password';     block = $true },
        @{ cmd = 'op item get Netflix --fields=type=concealed';     block = $true },
        @{ cmd = 'op item get X --share-link';                      block = $true },
        @{ cmd = 'FOO=bar op item get X --otp';                     block = $true },   # env prefix
        @{ cmd = 'op item list --format json';                      block = $false },
        @{ cmd = 'op item get Netflix --fields label=username';     block = $false },  # username not a secret label
        @{ cmd = 'op item get Netflix';                             block = $false },  # concealed by default
        @{ cmd = 'op vault list';                                   block = $false },
        @{ cmd = 'op';                                              block = $false },
        @{ cmd = 'git commit -m "op item get --otp"';              block = $false },   # not an op command
        @{ cmd = 'echo op item get --reveal';                       block = $false }   # echo, not op
    )
    $fail = 0
    foreach ($c in $cases) {
        $blocked = [bool](Test-Command $c.cmd)
        if ($blocked -ne $c.block) {
            $fail++
            Write-Host ("FAIL  expected block={0} got {1}  [{2}]" -f $c.block, $blocked, $c.cmd)
        }
    }
    if ($fail) { Write-Host "SelfTest: $fail FAILED"; exit 1 }
    Write-Host "SelfTest: all $($cases.Count) cases passed"; exit 0
}

# --- hook mode: read PreToolUse JSON from stdin ---
$raw = [Console]::In.ReadToEnd()
if (-not $raw) { exit 0 }
try { $payload = $raw | ConvertFrom-Json } catch { exit 0 }   # not JSON -> don't interfere
$cmd = $null
try { $cmd = [string]$payload.tool_input.command } catch { }
if (-not $cmd) { exit 0 }
$reason = Test-Command $cmd
if ($reason) {
    [Console]::Error.WriteLine("op-guard: blocked - $reason. This repo forbids printing secret values (CLAUDE.md: op/vault hygiene). Use metadata-only discovery (op item list, or op item get --fields label=<non-secret>); resolve real secrets only through the worker's single 'op inject' run in your own terminal.")
    exit 2
}
exit 0
