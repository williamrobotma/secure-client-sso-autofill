# Cisco Secure Client SSO one-press autofill - design

- Date: 2026-07-01
- Status: script implemented + committed; MVP testing in progress
- Repo: `secure-client-sso-autofill`
- Worked example: McGill VPN (`securevpn.mcgill.ca`)

## Current status / resume point

- **Stage:** dry-run validated end-to-end (2026-07-02); ready for live test.
- **Done:** research; this design; repo scaffolded and pushed; `sso-autofill.ps1`,
  `config.example.ps1`, README built + security-reviewed + committed. `op` +
  PowerToys installed; 1Password CLI desktop integration enabled. Native
  1Password auto-type evaluated live and rejected (see "Why not native
  1Password auto-type").
- **MVP scope:** core one-press flow only - `op` fetch + type username/password/
  TOTP into Cisco, each with Enter + a per-screen delay. Agreement auto-accept
  is DEFERRED: run with `HandleAgreement = $false` and click Accept manually
  (one click). Security essentials R1-R4 stay in the MVP; only the flaky
  agreement automation is out.
- **Next action:** config set (`OpVault=Personal`, `OpItem`=Mcgill item verified
  USERNAME/PASSWORD/OTP, `OpPath`=full op.exe path, `HandleAgreement=$false`).
  `-SelfTest` passes; `-DryRun` via the PowerToys hotkey completes end-to-end
  (2026-07-02) - all three masked fields land in Notepad. Next: LIVE test - remove
  `-DryRun` from the KBM Args, bring the Cisco login to front, press the chord,
  HANDS OFF while it fills the three SSO screens, then click Accept manually.
  Tune delays if a field lands on the wrong screen.
- **Findings (2026-07-02):**
  - `OpPath`: PowerToys was started before op's PATH entry, so a hotkey launch
    inherited a stale PATH and couldn't find bare `op`. Fixed with a configurable
    `OpPath` (full op.exe path in config.local.ps1).
  - Focus stability: the run needs the target window foreground for the whole
    ~7s (three fields + delays). Any focus change (e.g. Alt-tabbing away) makes
    R1 abort safely before the next field - so: launch, then hands off.
  - Error surface: a modal `MessageBox` hangs invisibly under a hidden launch
    (holding secrets); replaced with a self-closing popup + a secret-free
    `sso-autofill.log` stage/error trace (gitignored).
- **Execution:** PowerShell runs here now (the earlier deny-rule is off).
  `-SelfTest` is side-effect-free and Claude-runnable - R4 verified 2026-07-01,
  all cases pass. `-DryRun` and live runs must be launched interactively by the
  user (own terminal or the PowerToys hotkey), NOT from a background/headless
  shell: a background-spawned process can't grab window focus and hangs holding
  secrets in memory (seen 2026-07-01). They fetch real secrets (Windows Hello =
  user present) and risk account lockout, so the user launches and watches. See
  [CLAUDE.md](../CLAUDE.md) for the working rules.
- **Wrap-up condition (durable):** run the `security-review` skill on the
  pending changes before every commit / sync-point on this task.

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

### Why not native 1Password auto-type

1Password's desktop Auto-type (Quick Access -> Auto-Type) *does* inject
keystrokes into the Cisco embedded window - unlike the browser extension's
inline "Fill in Browser" (`Ctrl+\`), which only reaches supported browsers and
never the embedded WebView2. But Auto-type fires username -> Tab -> password ->
Enter as one burst, assuming a single login form. McGill's Microsoft SSO is
paginated (email, then password, then code on separate screens), so on the
email-only screen the burst's Tab moves focus off the field and the auto-submit
Enter follows whatever it landed on. Tested live 2026-07-01: auto-typing the
McGill item on the email screen navigated to Microsoft's "which type of account
do you need help with" page instead of advancing. Native auto-type is therefore
rejected for this flow; the per-screen script (one field + Enter + delay per
screen, no Tab) is what fits. Documented so it is not re-investigated.

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
  -> locate + verify identity + SetForegroundWindow(Cisco window)  [R1]
  -> re-verify foreground; type username; {ENTER}; sleep D1
  -> re-verify foreground; type password; {ENTER}; sleep D2
  -> re-verify foreground; type TOTP;     {ENTER}; sleep D3
  -> bounded-wait for agreement window; re-verify; accept
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

- Two `op` calls in one run (one Windows Hello unlock - the desktop-app session
  is cached across calls in the same run):
  1. `op item get $OpItem --vault $OpVault --format json` -> username + password
     from the fields whose `purpose` is `USERNAME` / `PASSWORD`.
  2. `op item get $OpItem --vault $OpVault --otp` -> the current TOTP code.
- Why two calls, not one: the full-item JSON carries the OTP field's
  `otpauth://` seed, not the computed 6-digit code, and `--otp` cannot be
  combined with `--format json` / `--fields`. Sequential calls in one run reuse
  a single unlock, so the "one Windows Hello prompt" goal still holds. (Resolves
  the build-time open item; this was the spec's sanctioned fallback, promoted to
  primary.)
- Requires `op` desktop-app integration + Windows Hello unlock enabled.

### Window targeting (the non-obvious safety point)

Launching the script can steal focus; typing a password into the wrong window
would leak it. So the script does not assume focus:

- Enumerate visible top-level windows (P/Invoke `EnumWindows`), pick the one
  whose title contains `WindowTitleMatch` **and** whose owning process is in
  `WindowProcessMatch` (process verified by image path/signature, not name
  alone - R1), then `SetForegroundWindow` it and re-verify before every
  field (R1).
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

The step-by-step setup (install `op` + PowerToys, create `config.local.ps1`,
bind the Keyboard Manager hotkey) is the user-facing guide and lives in
[../README.md](../README.md) as the **single source of truth** - deliberately
not duplicated here, so the two can't drift. This doc is the design + security
rationale; the README is how to install and run it.

## Security considerations

- Secrets stay in 1Password; retrieved on demand under Windows Hello; held only
  in script memory for the run; never written to disk or clipboard.
- Windows Hello prompt per run is a deliberate unlock gate, not a bug.
- Window-target check prevents typing secrets into an unintended foreground
  window.
- Personal identifiers (vault/item) live only in the gitignored
  `config.local.ps1`, never in the public repo.

## Security requirements (from review)

Binding requirements from the security review; verified at build/test. Each
refines the section(s) named in its ID.

- **R1 - Verify the target window's identity, and re-verify before every
  field** (refines "Data flow", "Window targeting"). The window-target check is
  the only thing preventing secrets from being typed elsewhere, so it must be
  both strict and repeated:
  - A match requires *both* the title (`WindowTitleMatch`) *and* the owning
    process (`WindowProcessMatch`), and the process is verified by image path
    (under `%ProgramFiles%\Cisco\...`) or Authenticode signature - never by
    process name alone, which is spoofable.
  - Immediately before each `SendWait` (username, password, OTP, agreement
    accept), re-read `GetForegroundWindow` and confirm it is still the
    validated target. If it changed, or if zero/many windows match, abort and
    type nothing further (fail-visible). Focus is not assumed to survive the
    inter-field delays.
- **R2 - `-DryRun` must not expose the real password** (refines
  "Configuration", "Testing plan"). Dry-run types masked values (length or
  asterisks), never the plaintext secret, into Notepad. Confirming retrieval is
  done on the masked form; plaintext is never placed anywhere it can be saved to
  disk.
- **R3 - No secret reaches logs, transcripts, or error text** (refines "Error
  handling"). No `Start-Transcript`; no `-Verbose` on the typing calls; no
  interpolation of a typed value into any message or `$_`. `*.log` is
  gitignored, but the requirement is that a secret is never written to a log in
  the first place.
- **R4 - `SendKeys` escaping is unit-checked; treat `SendKeys` as the weakest
  link** (refines "Typing"). Escaping of `+ ^ % ~ ( ) { } [ ]` is verified
  against a password containing every special character before live use (an
  unescaped `~`/`%`/`(` injects Enter/Alt/grouping). `SendKeys` can also
  drop/reorder keys under load; a dropped password character is a failed login,
  and repeated failures can lock the account - so typing is validated under
  `-DryRun` first.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Slow page load -> value lands on wrong screen -> failed login; repeated failures can lock the McGill account | Generous default delays; `-DryRun` validated first; user tests before live use; delays tunable |
| Launch steals focus -> keys go to wrong window | Script verifies the Cisco window's identity and re-verifies foreground before every field (R1); aborts if not found or focus changed |
| PowerToys not running | KBM only works with PowerToys running in background (documented) |
| Elevated Cisco window | KBM won't fire over an elevated window unless PowerToys is elevated; Cisco UI normally runs at user level (documented, verify if issues) |
| Agreement window detection flaky | Bounded wait + fail-visible exit; `HandleAgreement=false` to click manually |

## Testing plan

Note: PowerShell runs here now and `op` / PowerToys are installed. Claude can
run the side-effect-free `-SelfTest`; `-DryRun` and live runs are collaborative
(Windows Hello unlock is the user's; live runs risk account lockout).

1. Static review of the script + `-SelfTest` (Claude). Done: R4 self-test passes.
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

## Open items and build decisions

Resolved at build:
- **`op` retrieval:** two calls (JSON for username/password by field `purpose`;
  `--otp` for the current code), one Windows Hello unlock. See "Secret
  retrieval".
- **`-DryRun` is a script switch**, not a config value (an ad-hoc test toggle;
  `config.example.ps1` notes this). `-SelfTest` added to satisfy R4's
  "unit-checked before live use" without a separate test file.
- **Fail-visible under hidden launch:** errors surface via a `MessageBox` (there
  is no console when KBM runs the script hidden), with no secret in the text (R3).

Still to verify live (user testing):
- Exact Cisco login window title / owning process -> tune `WindowTitleMatch` /
  `WindowProcessMatch`.
- Agreement window detection (login vs agreement window) -> tune or disable.
- 1Password vault + item reference (user-provided, into `config.local.ps1`).
