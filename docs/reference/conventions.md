---
title: CLI conventions
description: The rules every jit command shares: global flags, output formats, confirmation flags, and exit codes.
---

# CLI conventions

Rules that hold across the whole CLI, so you learn them once instead of per
command. For the flags of a single command, see the
[command reference](./commands/jit.md) or `jit <command> --help`.

## Global flags

Three flags work everywhere:

| Flag | What it does |
|---|---|
| `--quiet` | Suppress the progress spinner and status trail on stderr. Results still print. Use it in scripts and CI, where a spinner is just noise in the log. |
| `-h`, `--help` | Help for that command. |
| `-v`, `--version` | Print the version (root only). `jit version` prints the same thing. |

`--quiet` only silences progress output. It never hides a result, a warning, or
an error.

## Output formats

Every command that can emit machine-readable output takes `--format`. Text is
always the default, and `json` always means "one JSON snapshot on stdout".

| Command | `--format` values |
|---|---|
| `jit status` | `text`, `json` |
| `jit doctor` | `text`, `json` |
| `jit service status` | `text`, `json` |
| `jit vault list` | `text`, `json` |
| `jit vault get` | `text`, `json` |
| `jit vault history` | `text`, `json` |
| `jit vault orphans` | `text`, `json` |
| `jit audit` | `text`, `json`, `logfmt` |
| `jit scan` | `text`, `markdown`/`md`, `ndjson` (no plain `json`) |

Two commands have a wider vocabulary because they emit a stream of records
rather than a snapshot:

- `jit audit --format logfmt` prints one `key=value` line per event, so it
  greps like a service log.
- `jit scan --format ndjson` prints one JSON record per finding plus a closing
  summary record. See [Scan NDJSON output](./scan-ndjson.md) for the schema.

`jit scan` also takes `-o`/`--output <file>` to write the report to a file
instead of stdout. A saved report never contains ANSI colour codes and keeps
absolute paths, so it stays readable to whatever reads it next.

## Text output adapts to a terminal. Piped output does not.

Several commands print a richer view when stdout is a terminal, and a plain,
stable view when it is piped or redirected. The piped form is the one to script
against:

| Command | On a terminal | Piped or redirected |
|---|---|---|
| `jit vault list` | Grouped under a header per path segment, with counts, flowed into columns | One full secret path per line, then a blank line and a two-line count summary |
| `jit vault get` | The value on stdout, plus a metadata line on **stderr** (last updated, referencing profiles, source file) | The value only, nothing on stderr |
| `jit vault list -l` | Annotates each secret with its class and age | Not rendered (terminal only) |

So `jit vault get path > file` writes just the value, with no flag needed.

One caveat on `jit vault list`: its trailing count summary goes to **stdout**,
not stderr, so it survives a pipe. `jit vault list | grep stripe` is fine (the
summary does not match), but a loop over every line will see it. Use
`--format json` when you want only data:

```bash
jit vault list --format json | jq -r '.secrets[].path'
```

## Confirmation flags

Anything destructive asks first. One flag skips the question, everywhere:

- **`-y`, `--yes`** skips a `[y/N]` confirmation. Same spelling on every
  command that has one.
- **`--force`** is reserved for a different job: overriding a precondition that
  would otherwise make the command a no-op. `jit upgrade --force` reinstalls a
  release you already have. It is not a confirmation flag.

`jit vault rm` and `jit vault set` still accept `-f`/`--force` as a synonym for
`--yes`, so the `rm -f` reflex and any existing script keep working.
`jit vault get --json` is likewise still accepted for `--format json`.

Skipping the typed confirmation never skips a **Touch ID or passcode** prompt.
`jit vault get`, `set`, `rm`, `uninstall`, and the rest that require local auth
still require it with `--yes`. That gate is not bypassable by a flag, on
purpose: a process running as you should not be able to read or destroy your
secrets without a live human gesture.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. Also a `jit scan` that found secrets, unless you asked for a gate (see below). |
| `1` | The command itself could not run: a bad flag, a path that does not exist, an unreadable vault root, a file that could not be restored (`jit migrate undo`). |
| `2` | The findings code, shared by `jit scan --fail-on` (the scan ran fine and its risk level reached your threshold) and `jit doctor` (something the setup depends on is broken; see below). |
| `127` | A wrap shim could not exec the real tool. Loud on purpose, never a silent unwrapped run. |

`jit scan` exits `0` by default even when it finds critical secrets, because a
read-only report is not a failure. To use it as a gate, give it a threshold:

```bash
jit scan --fail-on high        # exit 2 when risk is HIGH or CRITICAL
jit scan --fail-on any         # exit 2 on anything that is not clean
```

The status is `2` rather than `1` so a tripped gate is distinguishable from the
scan itself breaking. The report is always written in full first, so the gate
never costs you the findings that explain it.

`jit doctor` exits `2` when something the setup depends on is actually broken: a
secret missing, corrupt, or unparseable; the whole vault unreadable because this
Mac's master key is gone from the keychain or a master-key rotation never
finished; or a wrapped tool's install damaged (so it now runs unwrapped or not
at all). Everything else it reports (an orphaned secret, a stopped service, a
stale backup, a shim complaint that is only true of the shell you happen to be
in) is an advisory warning and stays `0`, so you can run it on every shell start
without it failing your prompt; `--strict` makes those advisories count too.
Exit `1` is reserved for doctor itself failing to run (a bad flag, an unreadable
vault root), which a pipeline needs to tell apart from a genuinely broken
machine.

## In CI or a script

The three conventions combine:

```bash
# Fail the build on a high-risk finding, quietly, with a machine-readable report.
jit scan --quiet --format ndjson -o findings.ndjson --fail-on high

# Check a migrated project's secrets still resolve. Exits non-zero if not.
jit doctor --quiet --format json > health.json
```

Neither command decrypts a secret, so neither needs an unlocked session or a
Touch ID prompt. Commands that *do* resolve secrets (`jit run`, `jit export`,
the credential helpers) need either a running unlocked service or an
interactive prompt, so they are not suited to a fully headless runner. See
[Plumbing protocols](./plumbing.md).
