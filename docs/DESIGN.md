# Cisco Secure Client SSO one-press autofill - design

- Date: 2026-07-01
- Status: approved (design); pending user spec review
- Repo: `secure-client-sso-autofill`
- Worked example: McGill VPN (`securevpn.mcgill.ca`)

## Context

Connecting to the McGill VPN via `securevpn.mcgill.ca` in Cisco Secure Client
(v5.1.7.80) requires an SSO login (Microsoft 365) across three sequential
screens - username, password, 2FA security code - followed by accepting a
connection agreement.

All three values live in 1Password, but 1Password does not autofill them. The
Cisco UI history log shows the SSO login runs in Cisco's *embedded* browser:
every `<webbrowser>` entry has `is_external="false"`, `type="browser_plugin"`,
`user_agent="AnyConnect/5.1.7.80 (win)"`. That embedded WebView2 window does
not load the Edge/Chrome 1Password extension, so extension autofill cannot
reach it. Result today: open 1Password three times, copy/paste each value, then
click Accept.

### Why not the zero-code path

Cisco can be made to run SSO in the real default browser (`is_external="true"`),
where the 1Password extension would autofill everything. That mode
(external-browser SAML) is negotiated with the head-end, not a client-side
switch: it requires `external-browser enable` on the ASA tunnel-group
(ASA 9.17.1+ / client 4.10.04065+). The logs show McGill forcing embedded mode
(`is_external="false"`, `acsamlcap=v2`) on every recent connect, so this is not
available unilaterally. It would require a request to McGill IT and is out of
scope. Documented so it is not re-investigated.

## Goals

- One keypress fills all three SSO screens and accepts the agreement.
- Secrets sourced from 1Password via the `op` CLI; never placed on the
  clipboard.
- Keep the existing Cisco Secure Client (McGill-managed routing/posture intact).
- Simple, readable, debuggable by the user; minimal moving parts.

## Non-goals

- Replacing the VPN client (openconnect-saml) - rejected as too heavy
  (Python + openconnect binary + wintun driver + admin; risks McGill
  routing/posture). Noted for completeness only.
- Fully unattended connect (no 1Password unlock, no keypress). Windows Hello
  unlock and one keypress are accepted steps.
- Robust page-load detection for the three SSO screens. The user chose
  "one press does all three" knowing it advances screens on fixed, tunable
  delays.

## Approach

Keep Cisco. Add a small PowerShell worker that pulls secrets from 1Password and
types them into the Cisco login window, triggered by a PowerToys Keyboard
Manager "Start App" shortcut.

Three independently-understandable pieces:

1. **`op` (1Password CLI)** - secret source. A single
   `op item get <item> --format json` call returns username, password, and the
   current TOTP together, so Windows Hello prompts once per run.
2. **`sso-autofill.ps1`** - worker. Sources local config, fetches secrets,
   finds and focuses the Cisco login window, types each field with Enter
   between them, then waits for and accepts the agreement.
3. **PowerToys Keyboard Manager** - trigger. "Remap shortcut -> Start App" runs
   the script with Visibility=hidden (no console flash) on a user-chosen chord.

### Data flow

```
keypress
  -> KBM launches powershell (hidden)
  -> op item get --format json        (1 Windows Hello unlock)
  -> locate + SetForegroundWindow(Cisco login window)
  -> type username; {ENTER}; sleep D1
  -> type password; {ENTER}; sleep D2
  -> type TOTP;     {ENTER}; sleep D3
  -> bounded-wait for agreement window; accept
```

Secrets exist only in script memory for the run: no clipboard, no disk.

## Script behavior

### Configuration (split for a public repo)

Machine-specific values live in `config.local.ps1`, which is **gitignored** so
personal vault/item identifiers are never committed. A committed
`config.example.ps1` documents every setting; setup is copy-to-local-and-edit.
The script dot-sources `config.local.ps1` and fails visibly if it is missing.

| Name | Purpose | Default (example) |
| --- | --- | --- |
| `OpVault` | 1Password vault name/UUID | user-provided |
| `OpItem` | 1Password item name/UUID (login with username+password+one-time-password) | user-provided |
| `DelayAfterUsername` | ms to wait after username+Enter | 2500 |
| `DelayAfterPassword` | ms to wait after password+Enter | 2500 |
| `DelayAfterOtp` | ms to wait after OTP+Enter | 2000 |
| `WindowTitleMatch` | substring to match the Cisco login top-level window title | `Cisco Secure Client` |
| `WindowProcessMatch` | owning process name(s) to match | `csc_ui.exe`, `acwebhelper.exe` |
| `HandleAgreement` | attempt to accept the agreement | true |
| `AgreementTimeoutMs` | max wait for the agreement window | 15000 |
| `AcceptKey` | keystroke sent to accept | `{ENTER}` |
| `DryRun` | log steps, type into Notepad instead of Cisco, no secrets to Cisco | false |

### Secret retrieval

- One call: `op item get $OpItem --vault $OpVault --format json`, parse JSON for
  the username field, password field, and the one-time-password field's current
  `totp` value.
- Rationale: one call = one Windows Hello prompt. (On Windows, each `op`
  invocation in a fresh sub-shell re-authorizes; minimizing calls minimizes
  prompts.)
- Requires `op` desktop-app integration + Windows Hello unlock enabled.
- Exact JSON field shape to be confirmed at build; fallback is separate
  `op read` (username/password) + `op item get --otp` calls.

### Window targeting (the non-obvious safety point)

Launching the script can steal focus; typing a password into the wrong window
would leak it. So the script does not assume focus:

- Enumerate visible top-level windows (P/Invoke `EnumWindows`), pick the one
  whose title contains `WindowTitleMatch` and/or whose owning process is in
  `WindowProcessMatch`, then `SetForegroundWindow` it before typing.
- If zero or more than one match, abort and type nothing (fail-visible).
- The embedded browser is hosted by `acwebhelper.exe` under the `csc_ui.exe`
  top-level window; the exact owning window/title must be verified live during
  testing, which is why both are config-driven.

### Typing

- `[System.Windows.Forms.SendKeys]::SendWait` per field, then a separate
  `{ENTER}` to advance.
- Passwords can contain `+ ^ % ~ ( ) { } [ ]`, which SendKeys treats as
  commands. The script escapes these (wrap each in `{ }`) so values type
  literally. Escaping is applied uniformly to all typed values (harmless for
  the email/digits, necessary for the password).
- Clipboard paste was considered and rejected: it defeats the no-clipboard goal.

### Agreement

- After the OTP step, poll (250 ms interval) up to `AgreementTimeoutMs` for the
  agreement window to appear, then `SetForegroundWindow` + send `AcceptKey`
  (default Enter = default button).
- Best-effort and the flakiest step (tunnel negotiation time varies). If the
  window is not found in time, log and exit so the user clicks Accept manually
  (one click). Exact detection of the agreement window vs the login window is a
  build/test-tuned detail; `HandleAgreement=false` disables it entirely.

### Error handling

- Fail-visible throughout: missing `op`, missing `config.local.ps1`, failed
  unlock, item not found, no/many window matches -> write a clear message and
  exit without typing.
- No silent fallbacks that could send secrets to the wrong place.

## Prerequisites and setup

1. Install PowerToys (not currently installed). Enable Keyboard Manager.
2. Install `op` (1Password CLI). In the 1Password app: Settings > Developer >
   "Integrate with 1Password CLI"; Settings > Security > "Allow Windows Hello
   to unlock 1Password".
3. Copy `config.example.ps1` to `config.local.ps1`; set the vault + item.
4. PowerToys KBM: Remap a shortcut -> Start App:
   - App: `powershell.exe` (or `pwsh.exe`)
   - Args: `-NoProfile -ExecutionPolicy Bypass -File "C:\Users\mawil\Developer\secure-client-sso-autofill\sso-autofill.ps1"`
   - Visibility: hidden
   - Chord: user's choice (must start with a modifier; e.g. Ctrl+Alt+M)

## Security considerations

- Secrets stay in 1Password; retrieved on demand under Windows Hello; held only
  in script memory for the run; never written to disk or clipboard.
- Windows Hello prompt per run is a deliberate unlock gate, not a bug.
- Window-target check prevents typing secrets into an unintended foreground
  window.
- Personal identifiers (vault/item) live only in the gitignored
  `config.local.ps1`, never in the public repo.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Slow page load -> value lands on wrong screen -> failed login; repeated failures can lock the McGill account | Generous default delays; `-DryRun` validated first; user tests before live use; delays tunable |
| Launch steals focus -> keys go to wrong window | Script locates and re-focuses the Cisco window before typing; aborts if not found |
| PowerToys not running | KBM only works with PowerToys running in background (documented) |
| Elevated Cisco window | KBM won't fire over an elevated window unless PowerToys is elevated; Cisco UI normally runs at user level (documented, verify if issues) |
| Agreement window detection flaky | Bounded wait + fail-visible exit; `HandleAgreement=false` to click manually |

## Testing plan

Note: the user's PowerShell deny-rule blocks Claude from executing the script;
`op` and PowerToys are not yet installed. Testing is user-driven.

1. Static review of the script (Claude).
2. After installs: run with `-DryRun` - confirm one Windows Hello prompt,
   correct username/password/OTP retrieved (typed into Notepad), correct step
   sequencing and delays.
3. Live: initiate a McGill connect, bring the login window to front, press the
   chord; confirm all three screens fill and the agreement is accepted.
4. Tune delays / window match / agreement handling as needed.

## Deliverables

- `sso-autofill.ps1` - the worker script.
- `config.example.ps1` - config template (committed).
- `config.local.ps1` - user's real config (gitignored).
- `README.md` - overview + setup + KBM config + test checklist + tuning notes.
- `docs/DESIGN.md` - this spec.

## Open items (resolved at build/test)

- Exact `op` JSON field shape for username/password/TOTP.
- Exact Cisco login window title/owning process (verify live).
- Agreement window detection specifics.
- 1Password vault + item reference (user-provided, into `config.local.ps1`).
