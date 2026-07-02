# secure-client-sso-autofill

One keypress to fill a Cisco Secure Client SSO login (Microsoft 365 /
Entra ID) from 1Password - username, password, and TOTP 2FA - then accept
the connection agreement. Worked example target: McGill University's VPN
(`securevpn.mcgill.ca`).

> **Vibecoded.** This repository was designed and written collaboratively
> with an AI assistant (Anthropic's Claude, via Claude Code). It was built
> through a research -> spec -> plan -> build -> test workflow with a human in
> the loop, but you should still read the script and understand what it does
> before running it - it types your credentials into a window on your behalf.

> **Status: ready for user testing.** The design is complete (see
> [`docs/DESIGN.md`](docs/DESIGN.md)) and the script (`sso-autofill.ps1`) is
> committed. It has not yet been run end-to-end against a live login (dry-run
> first, then live - see [Testing](#testing)).

## The problem

Cisco Secure Client runs Microsoft 365 SSO in an *embedded* browser window
(WebView2), not your real default browser. The 1Password browser extension
only sees Edge/Chrome, so it cannot autofill that embedded window. The result
is opening 1Password three times per connect and copy/pasting username,
password, and the rotating 2FA code, then clicking Accept.

Enabling Cisco's *external-browser* SAML (which would let 1Password autofill
natively, zero code) requires a server-side change on the VPN head-end, so it
is not available to end users unilaterally.

## How it works

Three small pieces:

1. **`op` (1Password CLI)** - retrieves username, password, and the current
   TOTP in a single call, unlocked by Windows Hello. Secrets never touch the
   clipboard.
2. **`sso-autofill.ps1`** (a PowerShell script) - finds and focuses the
   Cisco login window, then types each field with Enter between screens, and
   accepts the agreement.
3. **PowerToys Keyboard Manager** - binds a hotkey to launch the script
   ("Remap shortcut -> Start App", run hidden).

## Requirements

- Windows with Cisco Secure Client using M365/Entra SSO in the embedded
  browser.
- A 1Password login item holding username, password, and a one-time-password
  (TOTP) field - i.e. code-based 2FA, not push/number-match.
- [1Password CLI (`op`)](https://developer.1password.com/docs/cli/) with the
  desktop-app integration and Windows Hello unlock enabled.
- [PowerToys](https://learn.microsoft.com/windows/powertoys/) (Keyboard
  Manager enabled).

## Setup

### 1. Install prerequisites

- **1Password CLI (`op`)** - install, then in the 1Password app enable
  Settings -> Developer -> "Integrate with 1Password CLI", and Settings ->
  Security -> "Allow Windows Hello to unlock 1Password".
- **PowerToys** - install and enable Keyboard Manager.

### 2. Configure

Local, machine-specific settings (your vault and item names) live in
`config.local.ps1`, which is **gitignored** - your identifiers are never
committed.

```powershell
Copy-Item config.example.ps1 config.local.ps1
```

Edit `config.local.ps1` and set `$OpVault` and `$OpItem` to your vault and
login item (the item must have username + password fields and a
one-time-password / TOTP field - i.e. code-based 2FA, not push). Every other
setting has a working default you can tune later.

### 3. Bind the hotkey (PowerToys Keyboard Manager)

Keyboard Manager -> Remap a shortcut -> Start App:

- **App:** `powershell.exe` (or `pwsh.exe`)
- **Args:** `-NoProfile -ExecutionPolicy Bypass -File "C:\Users\mawil\Developer\secure-client-sso-autofill\sso-autofill.ps1"`
- **Visibility:** Hidden (no console flash)
- **Shortcut:** your choice, must start with a modifier (e.g. `Ctrl+Alt+M`)

PowerToys must be running for the shortcut to work. If the Cisco window is
elevated, PowerToys must also be elevated (the Cisco UI normally runs at user
level).

## Testing

Do this in order before relying on the hotkey. Errors surface as a dialog box
even when the script is launched hidden.

1. **Escaping self-test** (no `op`, no Cisco needed):
   ```powershell
   .\sso-autofill.ps1 -SelfTest
   ```
   Confirms SendKeys special-character escaping is correct (R4). Must print
   "All SendKeys escaping self-tests passed."
2. **Dry run** - open and focus **Notepad**, then:
   ```powershell
   .\sso-autofill.ps1 -DryRun
   ```
   Confirms one Windows Hello prompt and that username / password / OTP are
   retrieved. It types **masked** values (`u:****`, `p:****`, `otp:****`) into
   Notepad at the configured cadence - never the real secret.
3. **Live** - start a McGill connect, bring the Cisco SSO login window to the
   front, then press your hotkey. Confirm all three screens fill and the
   agreement is accepted.

### Tuning

- **A value lands on the wrong screen** -> increase `DelayAfter*` in
  `config.local.ps1`.
- **"No matching window found"** -> adjust `WindowTitleMatch` /
  `WindowProcessMatch` to the real Cisco login window (verify its title and
  owning process live).
- **Agreement not accepted** -> raise `AgreementTimeoutMs`, or set
  `HandleAgreement = $false` to click Accept manually.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design and the security
requirements (R1-R4) the script implements.

## Security

- Credentials are read from 1Password on demand, gated by Windows Hello, held
  only in memory for the run, and never written to disk or the clipboard.
- The script targets the Cisco login window explicitly and aborts if it cannot
  find it, so it will not type secrets into the wrong window.
- Automating a login with fixed timing carries a small risk of a value landing
  on the wrong screen; repeated failures can lock an account. A dry-run mode is
  provided for safe testing.

## License

[MIT](LICENSE).
