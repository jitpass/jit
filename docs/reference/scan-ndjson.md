---
title: Scan NDJSON output
description: The machine-readable schema behind jit scan --format ndjson.
---

# Scan NDJSON output

`jit scan --format ndjson` emits newline-delimited JSON: one **finding**
record per finding, then a single closing **scan summary** record. Values
are always masked previews - the NDJSON stream never contains a full
secret, same as every other scan format.

## Envelope fields (both record types)

| Field | Meaning |
|---|---|
| `record_type` | `"finding"` or `"scan_summary"` |
| `record_id` | unique per finding (`null` on the summary - `run_id` is already unique per run) |
| `schema_version` | schema version of this record shape |
| `scanner_name` / `scanner_version` | producer identification |
| `run_id` | shared by every record of one scan run |
| `scan_time` | ISO 8601 |
| `endpoint` | the scanned machine (host/user identification) |

## Finding records

| Field | Meaning |
|---|---|
| `finding_type` | the category (shell config, env file, credential file, …); `exposed_secret` is a vendor token or JWT found by **content**. Schema 0.9.0+ produced it only for a file named to `jit scan <path>`; 0.11.0+ also emits it from a machine-wide walk for files whose name says they hold credentials (`*credentials*.csv`, `jwt-secret.txt`, …). A content match is still required either way. `shell_history_secret` is a vendor-format credential recorded in a shell history file (`~/.zsh_history`, `~/.bash_history`, `$HISTFILE`, fish); its `remedy` is `migrate` (`jit migrate <historyfile>` vaults the value and redacts each occurrence in place), except when `production_indicator_match` is set - then it is `manual`, because clearing the recorded copy does not un-expose a production credential (schema 0.16.0+). `mcp_embedded_secret` covered only a server entry's `env` block until schema 0.17.0+, which also reports a credential passed by `--env-file` (the finding names the config, with the file in `evidence`), one baked into `args` including `docker run -e`, and a remote server's `headers` or `url`; the same bump adds `~/.claude.json`, Claude Code's own store, as a source. `agent_cached_secret` is a **verbatim copy** of a credential jit confirmed elsewhere in the same run, found in an AI coding agent's local cache (Claude Code's `file-history/`, `paste-cache/`, `shell-snapshots/` and transcripts, and the equivalents for other agents). It is the only finding type produced by corroboration rather than detection: there is no pattern behind it, and it never appears alone - `origin` is named in `evidence`, and it shares a `cause_group` with the finding that identified the value whenever that finding has one. Its `remedy` is always `manual`, because `jit migrate` rewrites the file a credential lives in and the cache copy is not that file (schema 0.18.0+) |
| `severity` | the finding's risk rating |
| `file_path`, `line` | where (`line` may be `null` for whole-file findings) |
| `key_name` | the variable/key name, when there is one. MCP findings outside an env block spell it `<server>/args[2]`, `<server>/header:Authorization` or `<server>/url`; an `--env-file` finding carries the bare server name (schema 0.17.0+) |
| `value_preview` | masked preview - never the full value |
| `production_indicator_match` | value or context looks like a *production* credential |
| `public_ip_match` | a public IP found in context, if any |
| `confidence` | how sure the scanner is this is a real secret |
| `evidence` | the one-line "why" shown in the human report |
| `already_masked` | the on-disk value was already a masked/placeholder shape |
| `archived` | the file sits under an archived/backup-looking directory (archive, backup, .trash, …); a flag to help you triage - name such a file (or its folder) explicitly in `jit migrate <path>` to convert it. Trash paths set this flag too but the human report gives them their own remedy ("empty the trash") instead of a migrate offer: migrating a file the user already decided to delete would preserve what deletion is about to fix (schema 0.7.0+) |
| `remedy` | who can act: `migrate` and `wrap` mean jit can (see `fix_command`), `manual` means only you can - rotate, delete, or seal, per `evidence` (schema 0.12.0+). An MCP credential in `args`, `headers` or `url` is always `manual`: the host builds that command line or sends that request itself, so there is nothing for jit to inject into (schema 0.17.0+) |
| `fix_command` | the exact runnable command when `remedy` is jit's; absent for `manual` (schema 0.12.0+) |
| `cause_group` | opaque id shared by findings describing the same underlying secret - the same masked value re-found in copies of a file. Collapse on it to count *secrets* instead of findings, the way the human report does. Absent for findings with no value (schema 0.12.0+). Identity is the full value, not the masked preview and not the key name, so one token reported by two scanners that name it differently (`internal-tool/GITHUB_TOKEN` in an MCP config, `GitHub Personal Access Token` in history) is one group (schema 0.16.0+) |
| `test_fixture` | the file is test scaffolding (a `*_test.go`, something under `testdata/`): the value matches a real credential format because that is what a scanner's fixtures are written to do, but nobody owns it and there is nothing to rotate. Reported in full, never counted toward the secret ledger (schema 0.13.0+) |
| `source_example` | the vendor match sits on a **comment line of a source-code file** - a pattern list's own examples, a doc comment arguing by example. It documents a shape rather than storing a credential. Reported in full, never counted toward the secret ledger, exactly like `test_fixture`. The accepted miss: a commented-out *real* credential in source is indistinguishable from an example and lands here too, which is why the human report's footer names the bucket rather than dropping it silently (schema 0.19.0+) |
| `origin_path` | the file this finding's credential actually lives in, when the finding is not that file: an `agent_cached_secret`'s source, or the credential file an MCP server reads via `--env-file`. A path, never a value. A finding carrying it is reported in full but does **not** add to `secrets_total` when the file it names carries a counted finding of its own - it is the same credential, counted where it lives (schema 0.19.0+) |
| `unfiltered_only` | this finding exists - or carries this severity - only because the run used `--unfiltered`; the everyday scan's suppression gates would hide or downgrade it. Absent on every normal run (schema 0.15.0+) |
| `unfiltered_reason` | the gate rule that fired, verbatim ("the name matched the browser-public build-variable rule (VITE_*)"), present exactly when `unfiltered_only` is (schema 0.15.0+) |

## The scan summary record

| Field | Meaning |
|---|---|
| `total_findings`, `findings_by_category` | counts |
| `risk_level` | the rolled-up machine rating from the human report |
| `production_indicator_count`, `public_ip_count` | how many findings raised each flag |
| `scan_duration_ms` | wall-clock scan time |
| `unfiltered` | `true` when the run used `jit scan --unfiltered`, which turns the name/value suppression gates off (schema 0.11.0+). A deliberately noisy auditing view - do not compare its counts against a normal run's |
| `secrets_total`, `secrets_protected`, `secrets_migratable` | the coverage ledger, in **distinct secrets**, never findings (13 copies of one dump are 3 secrets): everything jit knows about, how many are already served from the vault by live mounts, and how many of the exposed ones a bare `jit migrate` can protect. Only critical/high/medium findings count as secrets - low/info sightings are jit's own uncertainty, and `test_fixture` findings have no owner to rotate; neither is charged to the score (schema 0.12.0+, fixtures 0.13.0+). A `source_example` finding is likewise excluded - the human report's footer counts these as "source examples". Until schema 0.19.0 that marker was **not** serialized, so a consumer recomputing the ledger from records alone differed from `secrets_total` by exactly those findings; it is a field now. To recompute coverage: exclude `test_fixture`, `source_example` and low/info severities, drop every `agent_cached_secret`, drop any finding whose `origin_path` names a file that carries a counted finding **of its own** (a counted finding with no `origin_path` — a reference never vouches for another reference, so two findings pointing at each other both count), then count distinct `cause_group` (falling back to `record_id` when empty). One dedupe still cannot be reproduced - it compares **raw values** a file-level scanner parsed but reported only at file level (the `.env` that claims a credential the content sweep later re-finds in a paste cache), and those values are deliberately never serialized. Expect to land at or slightly above `secrets_total`, never below. An `mcp_embedded_secret` produced by a `--env-file` pointer does not add to `secrets_total` when the file it names carries a counted finding of its own - it is a link saying which server consumes that credential file, and the credential is counted where it lives; a pointer at a target the `.env` name gate drops is still counted, so nothing becomes invisible (schema 0.19.0+). A `cause_group` containing a `shell_history_secret` whose `remedy` is `manual` (production-flagged) is never counted in `secrets_migratable`, even when another finding in the group has remedy `migrate`: that history copy is live plaintext the recommended command will not touch, so the gain would not be real. An ordinary history finding is itself migratable and counts like any other (schema 0.16.0+). An `agent_cached_secret` **never** adds to `secrets_total`: a copy is the same secret in another place, and the finding that named it is already counted. It does make its origin file's `cause_group` non-migratable, for the same reason a manual history finding does - vaulting the `.env` while the agent's cache keeps the plaintext is not protection (schema 0.18.0+) |
| `targets` | the paths a targeted `jit scan <path>...` was aimed at, in the order given. **Absent on a machine-wide scan**, which is how a consumer tells the two apart - the human report's header uses the same distinction. Additive, so no schema bump |
| `files_scanned` | how many regular files the machine-wide walk offered to the classifiers; `0` for a targeted scan (schema 0.12.0+) |
| `degraded_scanners` | categories that could not complete, each `{scanner, error}` - e.g. a root-owned `~/.aws/credentials` left by a `sudo` run. **Absent on a clean run.** When present it changes what every count above it means: a `secrets_total` of `0` from a run with a degraded scanner is "we could not look there", not "there is nothing there" (schema 0.14.0+) |

A stream is well-formed when it ends with exactly one `scan_summary`
record; consumers can treat its absence as a truncated run.

One thing the human and markdown reports carry is deliberately absent here: the
**"Outside jit's scope, found anyway"** advisory, which names credentials other
tools minted for themselves (`~/.aws/cli/cache`, `~/.aws/sso/cache`,
`~/.aws/credentials-cache`, `~/.clisso.log`, assume-role profiles). If you diff NDJSON against the markdown report, that
difference is by design rather than a dropped record. This schema describes
findings jit stands behind and can act on; the advisory is a note to a human
about things jit deliberately does not manage, so it is never a finding, never
counted in any field above, and never affects `risk_level` or the coverage
ledger.
