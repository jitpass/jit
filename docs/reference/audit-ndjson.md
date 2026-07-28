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

## The scan summary record

| Field | Meaning |
|---|---|
| `total_findings`, `findings_by_category` | counts |
| `risk_level` | the rolled-up machine rating from the human report |
| `production_indicator_count`, `public_ip_count` | how many findings raised each flag |
| `scan_duration_ms` | wall-clock scan time |
| `unfiltered` | `true` when the run used `jit scan --unfiltered`, which turns the name/value suppression gates off (schema 0.11.0+). A deliberately noisy auditing view - do not compare its counts against a normal run's |

A stream is well-formed when it ends with exactly one `scan_summary`
record; consumers can treat its absence as a truncated run.
