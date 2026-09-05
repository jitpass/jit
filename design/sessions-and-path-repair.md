# Sessions, and repairing a recorded jit path

**Status: PR 1 shipped as #87 (2026-09-05). The "PR 2 — `jit doctor --fix`"
section below was superseded before it was built — `design/jit-path-refresh.md`
says why, and shipped as #88. The runbook edit is pending.**

## What prompted this

A morning lost to `clisso get` failing with `406 Not Acceptable`. The cause
was an expired OneLogin password (406 is OneLogin's lockout after repeated
failures; the honest 401 `Invalid user credentials` only shows once the
lockout clears), and jit was not involved. Taking the failure apart still
found three real defects in jit, and one in the runbook that wraps it.

What the investigation established, so nobody re-derives it:

- The config jit renders and serves over the FIFO reaches clisso complete
  and correct (`clisso --log-level debug get` prints every field it read).
  The OAuth call, whose only jit-supplied input is the vaulted
  client-secret, succeeds. jit contributes zero bytes to the call that
  fails.
- `clisso status` under the wrap is a pure `syscall.Exec` passthrough. It
  reads the on-disk config's `global.output: ~/.aws/credentials`, the file
  jit deliberately empties, and reports "No apps with valid credentials"
  while a valid session sits in the vault. Upstream cannot fix this either:
  clisso's `status` for `credential_process` mode is a bare `// TODO` that
  returns nothing. Every script that reuses a session by grepping
  `clisso status` (the team's `k8s` login function does) therefore
  re-logins with full MFA on every call.
- `jit doctor` reports a version-pinned `~/.kube/config` exec path
  (`Caskroom/jitpass/0.84.0/jit`, written before `internal/selfpath`) and
  prescribes `jit migrate ~/.kube/config`. On an already-migrated file that
  prints "Nothing to migrate" and changes nothing. There is no repair path
  for a recorded jit path anywhere in jit, and `kindJitPathUpgrade` names
  the same dead action.
- "Heal on `jit upgrade`" cannot work: a Homebrew jit refuses `jit upgrade`
  and hands off to `brew upgrade`, which never runs jit — and Homebrew is
  exactly where version-pinned paths come from. Repair must be explicit.
- `dev`/`admin` are NOT broken under the wrap. `StoreAWSSession` upserts the
  `credential_process` line into `~/.aws/config` on every capture; a profile
  is missing only until its first successful login.
- `jit status` opens the vault with `openVaultReadOnly()` — no unlock, by
  design. Any dashboard row must be answerable from envelope metadata
  (`Info()`), never from a decrypted value.

## PR 1 — sessions

### The feature

A **session** is a vaulted credential with a known end. jit already stores
one tool-agnostically: `EXPIRATION` is written by the clisso capture AND by
migrating a `~/.aws/credentials` that carries `aws_expiration` (aws sso,
saml2aws, aws-vault, any SAML minter), and `aws-credential-process` already
honors it, refusing a dead session by name. What is missing is a surface.
`jit status` shows expiry for grants and nothing for sessions.

Three layers, bottom up.

### Layer 0 — expiry as envelope metadata (`internal/vault`)

`Meta` and `SecretInfo` gain `ExpiresUnix int64`; the envelope gains
`expires_unix` (omitempty), AAD-bound like the timestamps and provenance,
and `envelopeVersion` moves to 5. Rationale: an expiry is not a secret
(the SDK receives it, clisso writes it in plaintext), and the dashboard
must read it without an unlock. Binding it into the AAD keeps the property
the `[storage format]` doctor finding exists for: a stamp edited on disk
fails decryption rather than resurrecting a dead session.

Writers: `StoreAWSSession` (capture) and the `~/.aws/credentials` migration
set it on every secret of the session from the parsed RFC3339 stamp. The
`EXPIRATION` variable stays — it is what `credential_process` serves — so
this is additive. A stamp that does not parse sets nothing, matching
`buildAWSCredentialProcessOutput`'s "pass it through, let the SDK complain"
rule.

Older envelopes have no stamp and render as unknown, never as 1970 — the
same rule `SecretInfo` already states for v1 timestamps. They heal on the
next login. `Verify`/`GetStored` accept version 5 the way they accept 4.

### Layer 1 — one query (`internal/migrate`)

    ListSessions(v *vault.Vault, root string, now time.Time) ([]Session, error)

For every profile manifest under root (global `~/.jit/profiles` for the
dashboard; `profile.ListAll` already enumerates) whose variables include
`EXPIRATION`: name, expiry, remaining, and the origin path from `Info()` —
which tool minted it. Keyed on the variable, not on a tool name, so a
future capture wrap (`aws sso login`, `gcloud auth`, `saml2aws`) is covered
by following the convention that already exists. Reads `Info()` only; never
`Get()`.

### Layer 2 — surfaces

**`jit status`** gains a `sessions` row beside `grants`, same shape
(`printGrantsSection` is the template), and a `sessions` object in
`--format json` so a script can ask without parsing text:

    sessions  2 valid · stage expires in 9h12m · prod expired 3h ago

Naming was checked: the dashboard renders the broker as
"unlocked / locks in", not "session", and "AWS session" is already the
code's and docs' word for a minted credential (38 uses vs 5 for the
broker's). No collision on the surface the user reads.

**`clisso status` under the wrap** becomes a third intercepted family in
`runClissoCapture`, beside `get` and the config mutators. Gated the way
`get` is: only when the on-disk config carries a `jit://vault` pointer (the
wrap owns it) and the user passed no `-r/--read-from-file` — an explicit
`-r` is the user asking for clisso's own behavior, the same rule `-o`
applies to `get`. It renders `ListSessions` filtered to the apps
`~/.clisso.yaml` defines — not to origin, which is birth-immutable and
would disown a profile first migrated out of `~/.aws/credentials` and
re-minted by clisso ever after — in clisso's own `App / Expire At /
Remaining` table (EXPIRE AT as a date and time, the one departure), so
`clisso status | grep -qw stage` and every other script keep working
unchanged. jit's stdout stays clisso-shaped on purpose; a jit-styled report
would break exactly the callers this fixes. jit's own commentary goes to
stderr, per the file's existing rule. Unlock-free, thanks to layer 0.

Held back, deliberately: a `jit status --session <name>` exit-code check for
scripts. `--format json` covers it; add the flag when a second script asks.

### Tests

- vault: v5 round-trip; a v4 envelope reads with `ExpiresUnix == 0`;
  editing `expires_unix` on disk fails decryption (AAD).
- migrate: `ListSessions` over a temp profiles dir with a live, an expired,
  a stampless (old) and a non-`EXPIRATION` profile; capture and
  credentials-migration both stamp; a malformed stamp stamps nothing.
- cli: the status row and JSON for 0 / 1 / n sessions, expired and live;
  `parseClissoArgs` routing for `status`, `status -r x`,
  `--log-level warn status`; the rendered table fed through `grep -qw`.
- Terminal output is previewed to the user before the row is wired
  (CLAUDE.md rule); `TestNoGlyphLiterals`/`TestPaletteIsCentralised` hold.

## PR 2 — `jit doctor --fix`

### Scope

One flag, one finding class: `[jit path]` (`kindJitPath` and
`kindJitPathUpgrade`). doctor stays a report; `--fix` is the narrow
exception, in the shape `jit vault orphans --prune` already has. Nothing
else in doctor becomes writable.

### One rule for detect and repair

Both use `jitPathArtifacts` (which files), `recordedJitPath` (which line),
and `selfpath.Durable()` (the answer). If `Durable()` refuses — a `/tmp` jit,
an unmatched Caskroom copy — doctor reports the refusal instead of writing.
It never records a path it would itself flag next run.

### Mechanics

Line-anchored substitution on the matched line only, so YAML, comments and
every other entry survive byte-for-byte; encrypted backup through
`BackupTracker.backupOnce` so `jit migrate undo` covers it; atomic write
via `vault.AtomicWriteFile`; mode preserved. Idempotent: a second `--fix`
finds nothing. Each rewrite prints one `✓` line naming the file and the
new path.

### Action text

Both kinds change from `jit migrate <file>` to `jit doctor --fix`. This is
the part that repairs trust regardless of whether anyone runs the flag: a
user who follows doctor's prescription and still sees `✗` stops believing
doctor.

### Deferred

Auto-heal from `jit service` at login (it runs after every `brew upgrade`).
Rewriting `~/.aws/config` unprompted from a daemon needs its own note; ship
the explicit form first.

### Tests

Golden files for each of the five artifacts: versioned → bin symlink;
already-durable → untouched; an unrelated `/usr/bin/jit` in a comment →
untouched; `Durable()` refusal reports and writes nothing; undo restores
the original.

## Runbook (Notion "Kubernetes Login V2") — no PR

- Session test: `aws sts get-caller-identity --profile "$env"` — truthful
  with or without jit, catches a revoked session (which `clisso status`
  never could), and works on a machine that has not picked up PR 1.
- The "must be sourced" guard is dead code in zsh: `BASH_SOURCE` is never
  set and `$0` is the file either way (verified, zsh 5.9). Use
  `[[ $ZSH_EVAL_CONTEXT == *:file:* ]]` for the zsh branch.
- Setup step 2: one sentence that on a jit machine `jit wrap clisso` moves
  the client-secret to the vault and leaves a `jit://vault/...` pointer in
  `~/.clisso.yaml`; that is expected.
- Troubleshooting entry, the lesson of the day: **401 = wrong password;
  406 = OneLogin lockout after repeated failures, almost always an expired
  password. Reset it in OneLogin, then `clisso providers passwd blockaid`.**
- Nothing about creating AWS profiles: the capture creates them.

## How the code gets written

The repo's conventions are the review checklist; the plan commits to them
up front rather than discovering them in review.

**Layering is fixed, and the plan respects it.** `vault` < `migrate` <
`cli`, with `selfpath` and `style` below all three. `ListSessions` lives in
`migrate` because it reads profile manifests and vault metadata and is
needed by two `cli` surfaces; the envelope field lives in `vault` because
nothing else may know the on-disk format. No new package: a `Session`
struct and one function are not a package.

**Pure core, thin shell.** The repo's stated pattern (`resolveRunPlan`,
`buildAWSCredentialProcessOutput`) is to split what a command decides from
the `RunE` that performs it, so the decision is testable without a vault
or a Touch ID. Applied here: `ListSessions` takes `now` as a parameter and
reads only `Info()`; the clisso table and the status row are pure renderers
over its result; the path repair is `repairRecordedPath(line, durable) ->
(newLine, changed)` with the file I/O around it. Every test in the plan is
a table test over these, not a pty capture.

**No speculative abstraction.** One `Session` type keyed on a variable, not
a `SessionProvider` interface with a clisso implementation. A second
capture tool changes nothing here — that is the test that the abstraction
is at the right altitude (`TECH_STACK.md` §3).

**Read the `doc.go` first, then write the `why`.** Comments in this tree
explain the decision and the failure it prevents, not what the line does.
Each new function carries the one it exists for: why expiry is metadata
(the dashboard is prompt-free), why the table is clisso-shaped (existing
grep callers), why `-r` opts out (the user asked for clisso's behavior),
why repair refuses on `Durable()` error (never record what doctor flags).

**Format compatibility is explicit.** Envelope v5 is additive: a v4 file
reads with `ExpiresUnix == 0`, `Verify`/`GetStored` list v5 beside v4, and
the "newer than this jit understands" error stays the answer for v6. The
test for "an edited stamp fails decryption" is what proves the field is
AAD-bound and not merely present.

**Output goes through the seam.** Every glyph and ink via `internal/style`
(`cOK`, `glyphOK`, …) — `TestNoGlyphLiterals` and `TestPaletteIsCentralised`
enforce it. One clause per line, ~72 chars, variable content truncated not
wrapped. The status row is previewed with a script the user runs at their
own width before it is wired (CLAUDE.md rule). clisso's table is the one
place house style does not apply: it is clisso's output, imitated on
purpose.

**Errors name the one command.** `"…; run `jit doctor --fix`"` — not a
paragraph, and never a command that does nothing, which is the defect PR 2
fixes.

**No new dependencies.** Both PRs are stdlib plus what is already in
`go.mod`. `TECH_STACK.md` §2 is not touched.

**Security annotations are justified, not sprinkled.** Any `#nosec` on the
file writes says why (fixed, jit-owned artifact paths), matching the
existing ones in `doctorsections.go`. The repair writes only lines that
matched `recordedJitPath` under the artifact's `Key`, so a hostile config
cannot steer it to rewrite something else.

**Every file carries the SPDX header**, `gofmt`/`vet`/`staticcheck`/
`gosec`/`govulncheck` at the pinned versions pass locally before push, and
`go run ./cmd/jit docs-gen` runs after the `--fix` flag lands (CI checks
`git status --porcelain`, so an untracked page fails it).

**One PR per feature, explicit staging.** `git add <paths>`, never `-A`;
`git diff --cached --name-only` before commit; no stash. Commit messages
in the tree's voice (`feat(status): …`, `fix(doctor): …`, one sentence
saying what changed for the user). No sign-off trailer on the maintainer's
own commits. No commits Sun–Thu 09:00–18:00.

## Order

PR 1 (layer 0 → 1 → 2, one PR, output preview before the row is wired),
PR 2, then the Notion edit. Each is independent of the others.
