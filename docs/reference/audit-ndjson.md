---
title: Audit NDJSON output
description: The machine-readable schema behind jit scan --format ndjson.
---

# Audit NDJSON output

`jit scan --format ndjson` emits newline-delimited JSON: one **finding**
record per finding, then a single closing **scan summary** record. Values
are always masked previews - the NDJSON stream never contains a full
secret, same as every other audit format.

## Envelope fields (both record types)

| Field | Meaning |
|---|---|
| `record_type` | `"finding"` or `"scan_summary"` |
| `record_id` | unique per finding (`null` on the summary - `run_id` is already unique per run) |
| `schema_version` | schema version of this record shape |
| `scanner_name` / `scanner_version` | producer identification |
| `run_id` | shared by every record of one audit run |
| `scan_time` | ISO 8601 |
| `endpoint` | the scanned machine (host/user identification) |

## Finding records

| Field | Meaning |
|---|---|
| `finding_type` | the category (shell config, env file, credential file, …); `exposed_secret` is a vendor token or JWT found by **content**. Schema 0.9.0+ produced it only for a file named to `jit scan <path>`; 0.11.0+ also emits it from a machine-wide walk for files whose name says they hold credentials (`*credentials*.csv`, `jwt-secret.txt`, …). A content match is still required either way |
| `severity` | the finding's risk rating |
| `file_path`, `line` | where (`line` may be `null` for whole-file findings) |
| `key_name` | the variable/key name, when there is one |
| `value_preview` | masked preview - never the full value |
| `production_indicator_match` | value or context looks like a *production* credential |
| `public_ip_match` | a public IP found in context, if any |
| `confidence` | how sure the scanner is this is a real secret |
| `evidence` | the one-line "why" shown in the human report |
| `already_masked` | the on-disk value was already a masked/placeholder shape |
| `archived` | the file sits under an archived/backup-looking directory (archive, backup, .trash, …); a flag to help you triage - name such a file explicitly in `jit migrate <path>` to convert it (schema 0.7.0+) |
| `remedy` | who can act: `migrate` and `wrap` mean jit can (see `fix_command`), `manual` means only you can - rotate, delete, or seal, per `evidence` (schema 0.12.0+) |
| `fix_command` | the exact runnable command when `remedy` is jit's; absent for `manual` (schema 0.12.0+) |
| `cause_group` | opaque id shared by findings describing the same underlying secret - the same masked value re-found in copies of a file. Collapse on it to count *secrets* instead of findings, the way the human report does. Absent for findings with no value (schema 0.12.0+) |
| `test_fixture` | the file is test scaffolding (a `*_test.go`, something under `testdata/`): the value matches a real credential format because that is what a scanner's fixtures are written to do, but nobody owns it and there is nothing to rotate. Reported in full, never counted toward the secret ledger (schema 0.13.0+) |

## The scan summary record

| Field | Meaning |
|---|---|
| `total_findings`, `findings_by_category` | counts |
| `risk_level` | the rolled-up machine rating from the human report |
| `production_indicator_count`, `public_ip_count` | how many findings raised each flag |
| `scan_duration_ms` | wall-clock scan time |
| `unfiltered` | `true` when the run used `jit scan --unfiltered`, which turns the name/value suppression gates off (schema 0.11.0+). A deliberately noisy auditing view - do not compare its counts against a normal run's |
| `secrets_total`, `secrets_protected`, `secrets_migratable` | the coverage ledger, in **distinct secrets**, never findings (13 copies of one dump are 3 secrets): everything jit knows about, how many are already served from the vault by live mounts, and how many of the exposed ones a bare `jit migrate` can protect. Only critical/high/medium findings count as secrets - low/info sightings are jit's own uncertainty, and `test_fixture` findings have no owner to rotate; neither is charged to the score (schema 0.12.0+, fixtures 0.13.0+) |
| `files_scanned` | how many regular files the machine-wide walk offered to the classifiers; `0` for a targeted scan (schema 0.12.0+) |

A stream is well-formed when it ends with exactly one `scan_summary`
record; consumers can treat its absence as a truncated run.

One thing the human and markdown reports carry is deliberately absent here: the
**"Outside jit's scope, found anyway"** advisory, which names credentials other
tools minted for themselves (`~/.aws/cli/cache`, `~/.aws/sso/cache`,
assume-role profiles). If you diff NDJSON against the markdown report, that
difference is by design rather than a dropped record. This schema describes
findings jit stands behind and can act on; the advisory is a note to a human
about things jit deliberately does not manage, so it is never a finding, never
counted in any field above, and never affects `risk_level` or the coverage
ledger.
