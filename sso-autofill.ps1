#requires -Version 5.1
<#
.SYNOPSIS
    One keypress: fill a Cisco Secure Client SSO login (username, password, TOTP)
    from 1Password, then accept the connection agreement.

.DESCRIPTION
    Pulls secrets from 1Password via the `op` CLI (one Windows Hello unlock),
    finds and focuses the Cisco login window, and types each field with Enter
    between screens on fixed, tunable delays. Secrets stay in memory for the run:
    never on the clipboard, never on disk.

    Settings live in config.local.ps1 (copy from config.example.ps1). See
    docs/DESIGN.md for the design and the security requirements R1-R4 this
    implements.

.PARAMETER DryRun
    Retrieve secrets (confirms the op path) but type MASKED values into Notepad
    instead of the real secret into Cisco. Open and focus Notepad first. (R2)

.PARAMETER SelfTest
    Unit-check the SendKeys escaping against a password containing every special
    character, then exit. Run this before first live use. (R4)

.NOTES
    Test order: -SelfTest (side-effect-free), then -DryRun (into Notepad), then
    live. Runs that fetch secrets prompt Windows Hello once per run.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
# Keep native-command failures out of the exception path so the op calls below
# report via our own $LASTEXITCODE checks (this variable only exists in PS 7.3+;
# assigning it is harmless on Windows PowerShell 5.1).
$PSNativeCommandUseErrorActionPreference = $false

# --- Logging (secret-free) -------------------------------------------------
# Stage + error trace to a gitignored log, reliable even under a hidden launch
# where a modal dialog can hang the process invisibly. Records stage names and
# error text ONLY - never a secret value (R3).
$script:LogPath = Join-Path (Split-Path -Parent $PSCommandPath) 'sso-autofill.log'
function Write-Log {
    param([string]$Message)
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue
}

# --- Win32 interop: enumerate top-level windows and control foreground focus ---
# Guarded so re-running in the same session (e.g. repeated -SelfTest) does not
# fail on a duplicate type definition.
if (-not ('Win32' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Win32 {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
'@
}
Add-Type -AssemblyName System.Windows.Forms

# --- SendKeys escaping (R4) ------------------------------------------------

function ConvertTo-SendKeysLiteral {
    # Escape every SendKeys metachar so the value types literally. Per-char
    # build (not sequential Replace) so brace escapes are not re-escaped:
    # '{' -> '{{}', '}' -> '{}}', '(' -> '{(}', etc.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $special = '+^%~(){}[]'
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $Text.ToCharArray()) {
        if ($special.IndexOf($ch) -ge 0) {
            [void]$sb.Append('{').Append($ch).Append('}')
        } else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

function Invoke-EscapingSelfTest {
    # R4: verify escaping renders every metachar literally before live use.
    # Vectors are fake test strings, not real secrets, so they are safe to print.
    $cases = [ordered]@{
        'a+b'                 = 'a{+}b'
        'x^y'                 = 'x{^}y'
        '50%'                 = '50{%}'
        'a~b'                 = 'a{~}b'
        '(p)'                 = '{(}p{)}'
        '{k}'                 = '{{}k{}}'
        '[i]'                 = '{[}i{]}'
        'P@ss+w0rd!(){}[]~%^' = 'P@ss{+}w0rd!{(}{)}{{}{}}{[}{]}{~}{%}{^}'
        'plain.123@ex.com'    = 'plain.123@ex.com'
    }
    $failures = 0
    foreach ($in in $cases.Keys) {
        $expected = $cases[$in]
        $got = ConvertTo-SendKeysLiteral $in
        $ok = $got -ceq $expected
        if (-not $ok) { $failures++ }
        '{0}  in=[{1}] expected=[{2}] got=[{3}]' -f `
            $(if ($ok) { 'PASS' } else { 'FAIL' }), $in, $expected, $got | Write-Host
    }
    if ($failures -gt 0) {
        throw "SendKeys escaping self-test FAILED ($failures case(s))."
    }
    Write-Host 'All SendKeys escaping self-tests passed.'
}

# --- Window targeting (R1) -------------------------------------------------

function Get-VisibleWindows {
    # All visible top-level windows with a non-empty title, as objects with
    # Handle / Title / ProcessId. Uses a script-scoped accumulator because the
    # EnumWindows callback runs from unmanaged code.
    $script:__enumWindows = New-Object System.Collections.Generic.List[object]
    $callback = [Win32+EnumWindowsProc] {
        param([IntPtr]$hWnd, [IntPtr]$lParam)
        if ([Win32]::IsWindowVisible($hWnd)) {
            $len = [Win32]::GetWindowTextLength($hWnd)
            if ($len -gt 0) {
                $sb = New-Object System.Text.StringBuilder ($len + 1)
                [void][Win32]::GetWindowText($hWnd, $sb, $sb.Capacity)
                $procId = [uint32]0
                [void][Win32]::GetWindowThreadProcessId($hWnd, [ref]$procId)
                $script:__enumWindows.Add([pscustomobject]@{
                    Handle    = $hWnd
                    Title     = $sb.ToString()
                    ProcessId = [int]$procId
                })
            }
        }
        return $true
    }
    [void][Win32]::EnumWindows($callback, [IntPtr]::Zero)
    return $script:__enumWindows
}

function Test-ProcessNameMatch {
    param([System.Diagnostics.Process]$Proc, [string[]]$Names)
    foreach ($n in $Names) {
        if ($n -ieq $Proc.ProcessName -or $n -ieq "$($Proc.ProcessName).exe") {
            return $true
        }
    }
    return $false
}

function Test-TrustedCiscoProcess {
    # R1: name match is necessary but not sufficient (spoofable). Require the
    # image path under a Cisco Program Files dir, or a valid Authenticode
    # signature from Cisco. If the path cannot be read, distrust (fail-visible).
    param([int]$ProcessId, [string[]]$Names)
    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $proc) { return $false }
    if (-not (Test-ProcessNameMatch -Proc $proc -Names $Names)) { return $false }

    $path = $null
    try { $path = $proc.Path } catch { $path = $null }
    if (-not $path) { return $false }

    $ciscoDirs = @(
        (Join-Path $env:ProgramFiles 'Cisco'),
        (Join-Path ${env:ProgramFiles(x86)} 'Cisco')
    )
    foreach ($d in $ciscoDirs) {
        if (-not $d) { continue }
        # Trailing separator: match the Cisco dir's *contents*, not a sibling
        # like 'Program Files\Cisco Evil\' that shares the 'Cisco' prefix.
        $prefix = $d.TrimEnd('\') + '\'
        if ($path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    $sig = Get-AuthenticodeSignature -FilePath $path
    if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate -and
        $sig.SignerCertificate.Subject -match 'Cisco') {
        return $true
    }
    return $false
}

function Find-SingleWindow {
    # Return the one visible window matching title + process, or throw if zero
    # or more than one match (fail-visible: never guess which window to type in).
    # -RequireCisco applies the strict process trust check (R1); without it
    # (dry-run -> Notepad) match by process name only.
    param(
        [string]$TitleMatch,
        [string[]]$ProcessNames,
        [switch]$RequireCisco
    )
    $hits = @()
    foreach ($w in Get-VisibleWindows) {
        if ($w.Title -notlike "*$TitleMatch*") { continue }
        if ($RequireCisco) {
            if (-not (Test-TrustedCiscoProcess -ProcessId $w.ProcessId -Names $ProcessNames)) {
                continue
            }
        } else {
            $p = Get-Process -Id $w.ProcessId -ErrorAction SilentlyContinue
            if (-not $p -or -not (Test-ProcessNameMatch -Proc $p -Names $ProcessNames)) {
                continue
            }
        }
        $hits += $w
    }
    if ($hits.Count -eq 0) {
        throw ("No matching window found (title '*$TitleMatch*', process " +
            "$($ProcessNames -join ', ')). Bring the target window to the front and retry.")
    }
    if ($hits.Count -gt 1) {
        throw ("Multiple matching windows found ($($hits.Count)); aborting to " +
            'avoid typing into the wrong one.')
    }
    return $hits[0]
}

function Assert-Foreground {
    # R1: confirm the validated target is still foreground right before typing.
    param([IntPtr]$Handle, [string]$Step)
    if ([Win32]::GetForegroundWindow() -ne $Handle) {
        throw "Foreground changed before '$Step'; aborting without typing (R1)."
    }
}

# --- Typing ----------------------------------------------------------------

function Send-KeysToTarget {
    # Re-verify foreground, type the (escaped) value, then optionally Enter.
    # Never logs or interpolates $Text (R3).
    param(
        [IntPtr]$Handle,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [string]$Step,
        [switch]$ThenEnter
    )
    Assert-Foreground -Handle $Handle -Step $Step
    [System.Windows.Forms.SendKeys]::SendWait((ConvertTo-SendKeysLiteral $Text))
    if ($ThenEnter) {
        Assert-Foreground -Handle $Handle -Step "$Step (Enter)"
        [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
    }
}

# --- Secrets ---------------------------------------------------------------

function Get-OpSecrets {
    # username + password from the item JSON (by field purpose); the current
    # TOTP code from `op item get --otp` (the JSON only carries the otpauth
    # seed, not the computed code). Two calls in one run = one Windows Hello
    # unlock. Values are returned in plain strings held only in memory.
    param([string]$Vault, [string]$Item, [string]$OpPath = 'op')

    if (-not (Get-Command $OpPath -ErrorAction SilentlyContinue)) {
        throw "1Password CLI not found at '$OpPath'. Set OpPath in config.local.ps1 to the full op.exe path (find it with: (Get-Command op).Source)."
    }

    $raw = & $OpPath item get $Item --vault $Vault --format json 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "op item get failed (exit $LASTEXITCODE). Check op is unlocked and the vault/item names are correct."
    }
    try {
        $parsed = $raw | ConvertFrom-Json
    } catch {
        # Generic message: never echo $raw, which holds the secret JSON (R3).
        throw 'Failed to parse the JSON returned by op item get.'
    }
    $username = ($parsed.fields | Where-Object { $_.purpose -eq 'USERNAME' } | Select-Object -First 1).value
    $password = ($parsed.fields | Where-Object { $_.purpose -eq 'PASSWORD' } | Select-Object -First 1).value

    $totp = & $OpPath item get $Item --vault $Vault --otp 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "op item get --otp failed (exit $LASTEXITCODE). Does the item have a one-time-password (TOTP) field?"
    }
    $totp = "$totp".Trim()

    if (-not $username) { throw 'No username field (purpose USERNAME) on the 1Password item.' }
    if (-not $password) { throw 'No password field (purpose PASSWORD) on the 1Password item.' }
    if (-not $totp)     { throw 'No TOTP code returned for the 1Password item.' }

    return [pscustomobject]@{ Username = $username; Password = $password; Totp = $totp }
}

# --- Agreement (best-effort) -----------------------------------------------

function Invoke-AcceptAgreement {
    # Poll for the Cisco window after the OTP step, focus it, and send AcceptKey.
    # Flakiest step (tunnel timing varies); on timeout, log and return so the
    # user clicks Accept manually. Distinguishing the agreement window from the
    # login window is a live-tuned detail - reuses the login match for now.
    param(
        [string]$TitleMatch,
        [string[]]$ProcessNames,
        [int]$TimeoutMs,
        [string]$AcceptKey
    )
    $deadline = [Environment]::TickCount + $TimeoutMs
    while ([Environment]::TickCount -lt $deadline) {
        $win = $null
        try { $win = Find-SingleWindow -TitleMatch $TitleMatch -ProcessNames $ProcessNames -RequireCisco }
        catch { $win = $null }
        if ($win) {
            [void][Win32]::SetForegroundWindow($win.Handle)
            Start-Sleep -Milliseconds 300
            if ([Win32]::GetForegroundWindow() -eq $win.Handle) {
                # AcceptKey is a SendKeys token ({ENTER}); do NOT escape it.
                [System.Windows.Forms.SendKeys]::SendWait($AcceptKey)
                return
            }
        }
        Start-Sleep -Milliseconds 250
    }
    Write-Verbose "Agreement window not confirmed within ${TimeoutMs}ms; accept it manually."
}

# --- User-facing error (visible even under a hidden KBM launch) -------------

function Show-FatalError {
    # Log first (reliable), then a self-closing popup. A modal [MessageBox]::Show
    # can hang invisibly under a hidden launch, holding secrets in memory; the
    # WScript.Shell popup auto-closes after a timeout, so it never hangs. Message
    # text never contains a secret (R3).
    param([string]$Message)
    Write-Log "ERROR: $Message"
    try {
        # Popup(text, secondsToWait, title, type). 0x10 = Stop icon; 0x1000 =
        # system-modal (topmost) so it shows above the Cisco window, not under it.
        [void](New-Object -ComObject WScript.Shell).Popup($Message, 15, 'SSO Autofill - error', 0x1010)
    } catch { }
    # -ErrorAction Continue: report to the error stream (for visible test runs)
    # without re-throwing out of the catch block under $ErrorActionPreference.
    Write-Error $Message -ErrorAction Continue
}

# --- Entry point -----------------------------------------------------------

if ($SelfTest) {
    Invoke-EscapingSelfTest
    return
}

try {
    Write-Log "=== run start (DryRun=$DryRun) ==="
    $scriptDir = Split-Path -Parent $PSCommandPath
    $configPath = Join-Path $scriptDir 'config.local.ps1'
    if (-not (Test-Path $configPath)) {
        throw "Missing config.local.ps1. Copy config.example.ps1 to config.local.ps1 and set OpVault/OpItem."
    }
    . $configPath

    $required = 'OpVault', 'OpItem', 'OpPath', 'WindowTitleMatch', 'WindowProcessMatch',
        'DelayAfterUsername', 'DelayAfterPassword', 'DelayAfterOtp',
        'HandleAgreement', 'AgreementTimeoutMs', 'AcceptKey'
    foreach ($name in $required) {
        if (-not (Test-Path "variable:$name")) {
            throw "config.local.ps1 is missing '$name'. Re-copy it from config.example.ps1."
        }
    }
    if ($OpVault -eq 'CHANGE-ME' -or $OpItem -eq 'CHANGE-ME') {
        throw 'Set OpVault and OpItem in config.local.ps1 (still at the CHANGE-ME placeholder).'
    }
    Write-Log 'config.local.ps1 loaded and validated'

    # Match the target window BEFORE fetching secrets. It is present at hotkey
    # time (verified live); matching first fails fast (no Windows Hello prompt)
    # if it is missing; and the Cisco login window's title can change during the
    # ~10s op/Hello wait, so matching afterward is unreliable.
    if ($DryRun) {
        $titleMatch = 'Notepad'
        $procNames = @('notepad')
    } else {
        $titleMatch = $WindowTitleMatch
        $procNames = $WindowProcessMatch
    }
    # Log the actual titles of visible windows owned by the target process(es),
    # so a failed match shows what was really on screen (title-independent view).
    $seen = Get-VisibleWindows | Where-Object {
        $cp = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
        $cp -and (Test-ProcessNameMatch -Proc $cp -Names $procNames)
    }
    Write-Log ('visible windows owned by [' + ($procNames -join ',') + ']: ' +
        (($seen | ForEach-Object { "'" + $_.Title + "'" }) -join ' | '))
    $target = Find-SingleWindow -TitleMatch $titleMatch -ProcessNames $procNames -RequireCisco:(-not $DryRun)
    Write-Log "target window matched (pid $($target.ProcessId))"

    # Retrieved in both modes to confirm the op path; typed masked in dry-run (R2).
    $secrets = Get-OpSecrets -Vault $OpVault -Item $OpItem -OpPath $OpPath
    Write-Log 'secrets retrieved (op unlock ok)'

    [void][Win32]::SetForegroundWindow($target.Handle)
    Start-Sleep -Milliseconds 300
    Assert-Foreground -Handle $target.Handle -Step 'focus target'
    Write-Log 'target is foreground; typing'

    if ($DryRun) {
        # R2: never type the plaintext; type a tag + asterisks of the same length.
        $userText = 'u:' + ('*' * $secrets.Username.Length)
        $passText = 'p:' + ('*' * $secrets.Password.Length)
        $otpText  = 'otp:' + ('*' * $secrets.Totp.Length)
    } else {
        $userText = $secrets.Username
        $passText = $secrets.Password
        $otpText  = $secrets.Totp
    }

    Write-Verbose 'Typing username'
    Send-KeysToTarget -Handle $target.Handle -Text $userText -Step 'username' -ThenEnter
    Start-Sleep -Milliseconds $DelayAfterUsername

    Write-Verbose 'Typing password'
    Send-KeysToTarget -Handle $target.Handle -Text $passText -Step 'password' -ThenEnter
    Start-Sleep -Milliseconds $DelayAfterPassword

    Write-Verbose 'Typing OTP'
    Send-KeysToTarget -Handle $target.Handle -Text $otpText -Step 'otp' -ThenEnter
    Start-Sleep -Milliseconds $DelayAfterOtp

    if ($HandleAgreement -and -not $DryRun) {
        Write-Verbose 'Waiting for agreement window'
        Invoke-AcceptAgreement -TitleMatch $WindowTitleMatch -ProcessNames $WindowProcessMatch `
            -TimeoutMs $AgreementTimeoutMs -AcceptKey $AcceptKey
    }

    Write-Log '=== run complete ==='
    if ($DryRun) {
        Write-Host 'Dry run complete: retrieved secrets and typed masked values into Notepad.'
    }
} catch {
    Show-FatalError $_.Exception.Message
}
