# Spec: gcloud's credential store, sealed in the vault

Status: approved for build 2026-10-02; phase A built (#210), phase B built
Scope: vaulting the gcloud CLI's own login store (`credentials.db`,
`legacy_credentials/`), the `jit gcloud-run` plumbing that materializes it
for one command, the `store` wrap kind and its five shims, undo.
Non-goals: minting tokens in jit (still deferred, `minting-broker.md` B),
the AWS SSO cache and the Azure token cache (each needs its own spike), and
application-default credentials, which `jit migrate` already vaults.

Evidence: `spike/gcloud-sealed-config/FINDINGS.md` (E1–E9, SDK 587.0.0).

## Problem

`~/.config/gcloud/credentials.db` holds a user refresh token with no fixed
expiry, in plaintext SQLite that gcloud writes itself. The same token sits in
`legacy_credentials/<account>/adc.json` and `.boto`. gcloud has no keychain
option. jit reports the store (issue #93) but cannot fix it: a FIFO cannot
serve SQLite, a decoy logs gcloud out, and the finding is excluded from
coverage because "sign out and back in" recreates the same file.

`minting-broker.md` rejected protecting tool-minted stores partly because
they "self-expire" and nobody asked. Both reasons fell: this token does not
expire, and supply-chain worms harvest exactly these files at install time
(Shai-Hulud 2.0, Nov 2025: 300 GCP credentials verified exposed; Unit 42).

## The mechanism

gcloud reads its whole config dir from `CLOUDSDK_CONFIG`. So the secrets
need not live in `~/.config/gcloud` at all:

```
at rest   vault: gcloud-cli/store  (tar of credentials.db + legacy_credentials/)
          ~/.config/gcloud: settings only (configurations/, active_config, logs/ …)

gcloud …  shim → jit gcloud-run --real <gcloud> -- …
          1. unpack the store into <jit root>/gcloud-run/<id>/   (0700; consent names gcp)
          2. symlink every settings entry of ~/.config/gcloud beside it
          3. fork gcloud with CLOUDSDK_CONFIG=<that dir>, stdio inherited
          4. wait; repack the secret set; re-vault only if the bytes changed
          5. move any NEW settings entry gcloud created into ~/.config/gcloud
          6. remove the dir; exit with gcloud's status
```

### Decisions

**D1. The CLI forks and waits; no service lease.** The spike proposed a
service-owned lease because a shim `exec`s. `jit clisso-capture` already
shows the other shape: fork, wait, write the vault, propagate the exit code
(`clissocapture.go`). It needs no protocol change, no new op and no app
change, and it puts the cleanup in the one process that knows when the tool
ended. What it gives up, and how that is covered:

- a SIGKILLed `gcloud-run` leaves its dir behind. Every run sweeps dirs whose
  owner (pid plus fork time, `lineage.ProcessStartTime`) is gone, before it
  makes its own. A later phase adds the same sweep to service start and a
  doctor finding.
- a gcloud that runs across a screen lock keeps its dir until it exits. That
  is the same exposure as the process's own memory, and the spike measured
  ordinary commands at under a second.

A service lease stays possible later without changing the vault layout.

**D2. One vault value, class `gcp`.** The secret set is packed as one tar:
one decrypt per run, so one consent prompt, and the sentence names the
`gcp` credential the user already knows from ADC. The tar is canonical
(sorted entries, zero times, fixed owner) so the bytes are a pure function
of the content, which is what D4 compares.

**D3. `access_tokens.db` is never vaulted.** It holds hour-long access
tokens and changes on every refresh, so vaulting it would mean a vault write
(and, past the session's idle TTL, a Touch ID) after ordinary commands.
gcloud recreates it when it is missing (measured), so each run starts
without it and pays one token refresh. The dir is removed after the run, so
the access token never rests on disk either.

**D4. Re-vault only on change.** After the run the secret set is repacked
and compared byte for byte with what was unpacked. Measured on real gcloud:
the bytes do not change across `auth list`, `config list`,
`print-access-token`, `projects list`, `config set`, `config-helper`, or a
refresh. They change on `auth login`, `auth activate-*` and `auth revoke`:
commands a human runs at the keyboard, where a Touch ID is expected. gcloud
does not persist a rotated refresh token on refresh (E4), so no silent
rotation is lost.

**D5. Logging in is captured, not refused.** With the wrap in place and no
store yet (a new Mac, or after `auth revoke --all`), the run materializes an
empty secret set, so `gcloud auth login` writes into the private dir and D4
vaults it. Nothing ever lands in `~/.config/gcloud`.

**D6. The private dir lives in jit's root, not `$TMPDIR`.** Same reason as
`newJobScratch`: a same-user process watching `$TMPDIR` could plant a file
between creation and use. `<root>/gcloud-run/` is 0700 and each run's dir is
0700.

**D7. Passthrough, never a broken gcloud.** `gcloud-run` execs the real tool
unchanged when:

- the user set `CLOUDSDK_CONFIG` to a dir other than the default (their own
  arrangement; only `~/.config/gcloud` is sealed in this phase);
- plaintext secrets are back in `~/.config/gcloud` (something logged in
  without the shim, an IDE using an absolute path). It says so on stderr,
  with the command to seal again, and lets gcloud use them: a wrapper that
  silently swaps in an older vaulted login would be worse.

**D8. Five shims, one kind.** The spike's E6–E8 found who reads the store:

| Name | Why it needs a shim |
|---|---|
| `gcloud` | the CLI itself; also covers `gke-gcloud-auth-plugin`, which runs `gcloud config config-helper` from PATH |
| `bq` | its own entry point; reads the store through gcloud's library |
| `gsutil` | its own entry point; reads `legacy_credentials/<account>/.boto` |
| `docker-credential-gcloud` | docker runs it by name; it loads gcloud's library in-process |
| `git-credential-gcloud` | git runs it by name; same |

They share one wrap kind, `store`, and one manifest field (`Store:
"gcloud"`). `jit wrap gcloud` installs all five whose real tool is on PATH.
Each has its own catalog entry and docs page, as `plugins_doc_test` requires.

**D9. Application-default credentials keep working inside the run.** The old
`gcloud` wrap was a grant wrap (`jit run --with gcp`). When the gcp mount
exists, `gcloud-run` registers the same grant on its own pid before forking,
so the child (a descendant) gets the real ADC exactly as before. An existing
grant-wrap manifest entry keeps working until the user re-runs
`jit wrap gcloud`.

**D10. Sealing is a backed-up move.** `jit wrap gcloud` backs up each
plaintext file (credentials.db, every file under legacy_credentials/,
linked with `RestoreWith`), vaults the tar, then removes the originals and
`access_tokens.db`. A re-vault after a login records fresh backups, so
`jit migrate undo ~/.config/gcloud/credentials.db` and
`jit uninstall --restore` put back the latest login, not the one from the
day of the wrap. `jit wrap undo gcloud` writes the current store back
(fresh Touch ID, as every plaintext-restoring action), removes the shims and
keeps the vault copy.

## Phases

**A (this change):** `internal/sealstore`, `jit gcloud-run`, the `store`
kind with its five catalog entries and docs, seal and undo, CLAUDE.md and
`wrap/doc.go` prose.

**B (built):** making the sealed store a first-class citizen everywhere
else jit looks.

- *Referenced, never an orphan.* A store-wrap is a new launcher kind
  (`launchers.KindStoreWrap`, `Map.StoreWraps`): the wrap manifest uses the
  sealed store's vault path the way a pointer file does. `jit vault orphans`
  never offers to prune it, `jit vault rm` names what still unseals it,
  doctor's orphan check honours it (and pointer files, which it had missed),
  and `jit status` counts it as managed elsewhere. After `jit wrap undo` the
  kept vault copy is a genuine orphan again.
- *Scan.* The store findings carry `jit wrap gcloud` as their fix and count
  in the ledger: they left the tool-minted class, because the wrap is a fix
  that does not reproduce the plaintext. Coverage follows the existing wrap
  rule rather than a new protected source: a wrapped tool's secret leaves
  Exposed and was never in Protected (only live mounts are), so the sealed
  store does the same. Bare `jit migrate` plans the wrap like any other.
- *Logs.* gcloud logs every command's arguments, so a token typed on a
  gcloud command line sits in `~/.config/gcloud/logs` for 30 days, where no
  sweep looked. `scanGcloudLogs` reads them, with the arrow "revoke it,
  log in again, then delete the log". Google OAuth refresh (`1//0`) and
  access (`ya29.`) tokens joined the shared format catalog, so the deep
  scan, transcript redaction and the audit-log masker know them too.
- *Leftovers.* The service sweeps dead runs' folders at start, before the
  socket opens. Doctor's wrap section reports a leftover folder and a
  plaintext store that came back while wrapped.
- *Remove JitPass.* `uninstall --restore` planned the deleted store files as
  Gone and lost the login. It now restores one `store` item from the
  vault's current copy (the latest login), unless a plaintext login is
  already there.

## Limits, stated plainly

- While a gcloud command runs, its dir holds the refresh token in plaintext,
  readable by any process running as the user. The promise is no plaintext
  at rest, not none in use.
- A program that runs gcloud by absolute path, or reads the store directly,
  sees "no active account". That is loud and fixable, never a silent leak.
- Each run pays one token refresh (D3).
