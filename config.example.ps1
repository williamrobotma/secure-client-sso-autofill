# config.example.ps1 - template for sso-autofill.ps1
#
# Setup: copy this file to config.local.ps1 (gitignored) and edit the two
# user-provided values (OpVault, OpItem). Everything else has a working default
# you can tune later. sso-autofill.ps1 dot-sources config.local.ps1 and fails
# visibly if it is missing.
#
#   Copy-Item config.example.ps1 config.local.ps1
#
# Note: -DryRun is a script parameter, not a config value. Run
#   .\sso-autofill.ps1 -DryRun   (types masked values into Notepad)
#   .\sso-autofill.ps1 -SelfTest (unit-checks SendKeys escaping, R4)

# --- 1Password source (REQUIRED - set these) ---

# Vault name or UUID that holds the login item.
$OpVault = 'CHANGE-ME'

# Login item name or UUID. Must have username + password fields and a
# one-time-password (TOTP) field, i.e. code-based 2FA (not push/number-match).
$OpItem = 'CHANGE-ME'

# Path to the 1Password CLI. 'op' works if op is on PATH for the process that
# launches this script. Set a FULL path (find it with: (Get-Command op).Source )
# if a hotkey launch reports "op not found" - PowerToys started before op was
# added to PATH inherits a stale PATH and can't resolve bare 'op'.
$OpPath = 'op'

# --- Timing (ms) - tune if a value lands on the wrong SSO screen ---

# Wait after username + Enter (username screen -> password screen).
$DelayAfterUsername = 2500

# Wait after password + Enter (password screen -> 2FA screen).
$DelayAfterPassword = 2500

# Wait after OTP + Enter (2FA screen -> connection agreement). Only used when
# HandleAgreement is $true; otherwise the run ends right after the OTP.
$DelayAfterOtp = 2000

# --- Window targeting (the safety check - see R1 in docs/DESIGN.md) ---

# Substring matched (case-insensitive) against the Cisco login window title.
# '- Login' pins the acwebhelper form window; bare 'Cisco Secure Client' also
# matches the csc_ui main window and trips the multiple-match abort when both
# are visible (found live 2026-07-02).
$WindowTitleMatch = 'Cisco Secure Client - Login'

# Owning process name(s) the window must belong to. The process is additionally
# verified by image path (under a Cisco Program Files dir) or Authenticode
# signature - process name alone is spoofable. Verify the real owner live:
#   the embedded browser is hosted by acwebhelper.exe under the csc_ui.exe
#   top-level window.
$WindowProcessMatch = @('csc_ui.exe', 'acwebhelper.exe')

# --- Connection agreement (best-effort final step) ---

# Attempt to accept the agreement after the OTP step. Deferred for the MVP
# (flakiest step; see DESIGN.md): leave $false and click Accept manually (one
# click); re-enable once the login flow is tuned.
$HandleAgreement = $false

# Max time (ms) to wait for the agreement window before giving up (then you
# click Accept manually - one click).
$AgreementTimeoutMs = 15000

# Keystroke sent to accept. {ENTER} triggers the default button. This is a
# SendKeys token, not a literal string, so it is not escaped.
$AcceptKey = '{ENTER}'
