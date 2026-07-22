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

## Commit gate + edit verification

- **Commits are gated on the security review** (DESIGN.md wrap-up condition):
  a native git pre-commit hook (`.githooks/pre-commit`) runs
  `.claude/hooks/review-gate.ps1 -CheckCommit`, which aborts the commit unless
  the gitignored `.claude/review-stamp` matches the staged diff. It fires only
  inside Claude Code's Bash env (`CLAUDECODE=1`); a human commit from a normal
  terminal is ungated.
  - **One-time per clone:** `git config core.hooksPath .githooks` (local config,
    not tracked - the gate is silently inactive until this is set).
  - Protocol: `git add -A` -> run the `security-review` skill -> stamp with
    `powershell -NoProfile -File .claude/hooks/review-gate.ps1 -Stamp` -> commit.
    Any further edit invalidates the stamp (re-review, re-stamp).
- Because git runs the hook against the real index at commit time, spelling no
  longer matters for staged content (env prefixes, `cd ... && git commit`,
  compounds, `cherry-pick -n` are all covered - the old regex/`if`-filter gaps
  are gone). Residual gaps: a partial commit (`git commit <pathspec>`) hashes
  only the pathspec'd temp index and never matches the full-tree stamp
  (blocked); empty-diff spellings (`--amend` with a clean index or a message
  reword, `--allow-empty`) stage no diff, so the gate allows them (benign - no
  reviewable content); `--no-verify` skips the hook (deliberate spelling,
  outside the forgetting-not-malice threat model).
- **Every Edit/Write of a `.ps1`** runs `.claude/hooks/verify-ps1.ps1`
  (parse check + `sso-autofill.ps1 -SelfTest`) as a PostToolUse hook in
  `.claude/settings.json`; failures are fed back to Claude automatically, so a
  broken edit is caught at edit time.

## op / vault hygiene

- Every `op` invocation re-prompts Windows Hello (brief cache only for
  back-to-back calls in one shell). Minimize calls; don't re-run on formatting
  errors - fix the formatting client-side. The steady-state run is the single
  `op inject` call `Get-OpSecrets` makes (a template of `op://` references
  resolving username + password + computed TOTP in one authorization).
- Never print secret field values. When inspecting an item, select only
  `id`/`label`/`purpose`/`type`; never `value` or `--otp` output.
