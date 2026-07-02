# CLAUDE.md - secure-client-sso-autofill

Project-scoped working notes for this repo. Design + security requirements live
in [docs/DESIGN.md](docs/DESIGN.md).

## Running the PowerShell worker (Windows)

- **Quoting `powershell.exe -Command` from the Bash tool (Git Bash):** wrap the
  script in SINGLE quotes so bash doesn't expand `$_`/`$var`/`$(...)` before
  PowerShell sees them (a double-quoted `$_.Prop` reaches PS as garbage ->
  parse error). Use `"..."` for any string literals inside.
- **Don't launch the GUI-automation runs (`-DryRun`, live) via the Bash tool.**
  A background-spawned process has no interactive desktop/foreground:
  `SetForegroundWindow` fails, so it can't focus the target, hangs on the
  invisible error dialog, and leaves the fetched secrets in process memory
  (seen 2026-07-01, hung ~30 min). Claude may run `-SelfTest` (side-effect-free)
  and `op` discovery; the user launches `-DryRun` / live in their own terminal
  (or the PowerToys hotkey), where focus works.
- **`-DryRun` types into whatever Notepad window/tab is FOCUSED** - it will
  write into a real open file. Use a fresh blank Notepad, never one holding real
  content (2026-07-01: masked values landed in the user's `~/.ssh/config`).

## op / vault hygiene

- Every `op` invocation re-prompts Windows Hello (brief cache only for
  back-to-back calls in one shell). Minimize calls; don't re-run on formatting
  errors - fix the formatting client-side. The steady-state run is the two
  calls `Get-OpSecrets` makes (`op item get --format json` + `--otp`).
- Never print secret field values. When inspecting an item, select only
  `id`/`label`/`purpose`/`type`; never `value` or `--otp` output.
