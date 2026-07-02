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

## Commit gate + edit verification (hooks in .claude/settings.json)

- **Commits are gated on the security review** (DESIGN.md wrap-up condition):
  a PreToolUse hook (`.claude/hooks/review-gate.ps1`) denies `git commit`
  unless the gitignored `.claude/review-stamp` matches the staged diff.
  Protocol: `git add -A` -> run the `security-review` skill -> stamp with
  `powershell -NoProfile -File .claude/hooks/review-gate.ps1 -Stamp` -> commit.
  Any further edit invalidates the stamp (re-review, re-stamp).
- Known gaps (threat model is forgetting, not malice): mixed compounds hide
  the commit from the hook's `if` filter (`cd ... && git commit`), and a
  git-only compound that materializes content mid-command bypasses the
  state snapshot (`git cherry-pick -n X && git commit`). Keep `git commit`
  standalone; a trailing `&& git push` is fine.
- **Every Edit/Write of a `.ps1`** runs `.claude/hooks/verify-ps1.ps1`
  (parse check + `sso-autofill.ps1 -SelfTest`); failures are fed back to
  Claude automatically, so a broken edit is caught at edit time.

## op / vault hygiene

- Every `op` invocation re-prompts Windows Hello (brief cache only for
  back-to-back calls in one shell). Minimize calls; don't re-run on formatting
  errors - fix the formatting client-side. The steady-state run is the two
  calls `Get-OpSecrets` makes (`op item get --format json` + `--otp`).
- Never print secret field values. When inspecting an item, select only
  `id`/`label`/`purpose`/`type`; never `value` or `--otp` output.
