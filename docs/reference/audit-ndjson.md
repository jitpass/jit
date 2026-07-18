---
title: Audit NDJSON output
description: The machine-readable schema behind jit audit --format ndjson.
---

# Audit NDJSON output

`jit audit --format ndjson` emits newline-delimited JSON: one **finding**
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
| `finding_type` | the category (shell config, env file, credential file, …) |
| `severity` | the finding's risk rating |
| `file_path`, `line` | where (`line` may be `null` for whole-file findings) |
| `key_name` | the variable/key name, when there is one |
| `value_preview` | masked preview - never the full value |
| `production_indicator_match` | value or context looks like a *production* credential |
| `public_ip_match` | a public IP found in context, if any |
| `confidence` | how sure the scanner is this is a real secret |
| `evidence` | the one-line "why" shown in the human report |
| `already_masked` | the on-disk value was already a masked/placeholder shape |
| `archived` | the file sits under an archived/backup-looking directory; `jit migrate` skips it unless `--include-archived` (schema 0.7.0+) |

## The scan summary record

| Field | Meaning |
|---|---|
| `total_findings`, `findings_by_category` | counts |
| `risk_level` | the rolled-up machine rating from the human report |
| `production_indicator_count`, `public_ip_count` | how many findings raised each flag |
| `scan_duration_ms` | wall-clock scan time |

A stream is well-formed when it ends with exactly one `scan_summary`
record; consumers can treat its absence as a truncated run.
