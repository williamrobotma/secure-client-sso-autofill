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

> **Status: early / work in progress.** The design is complete (see
> [`docs/DESIGN.md`](docs/DESIGN.md)); the helper script is not committed yet.

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

Local, machine-specific settings (your vault and item names) live in a
`config.local.ps1` that is **gitignored** - your identifiers are never
committed. Copy `config.example.ps1` to `config.local.ps1` and edit it.

Full setup and tuning steps will be added with the script. See
[`docs/DESIGN.md`](docs/DESIGN.md) for the current design.

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
