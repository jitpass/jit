---
title: Running an audit
description: jit scan - a strictly read-only scan for plaintext secrets exposed on this machine.
---

# Running an audit - `jit scan`

`audit` answers one question: **is my machine clean?** It is strictly
read-only under every flag: it never touches, encrypts, or rewrites
anything, and never prints a real secret value in full, only a masked
preview.

```
$ jit scan
jit scan: risk report for alex@Alexs-MacBook-Pro
scan time: 2026-07-07T14:48:08.370Z          duration: 2ms

  RISK LEVEL: HIGH
  EXPOSURE:   65/100

  Shell Configs          1 finding(s)
  .env Files             1 finding(s)
  Credential Files       0 finding(s)
  AI Tool / MCP Configs  0 finding(s)
  Private Keys           0 finding(s)
  IaC Variable Files     0 finding(s)
  Suspicious Filenames   0 finding(s)
  Wrappable CLI Tokens   0 finding(s)
  ───────────────────────────────────
  Total: 2 finding(s)

[Shell Configs]
  ───────────────────────────────────
  • /Users/alex/.zshrc

    :1  HIGH  AWS_SECRET_ACCESSKEY  AKIA**********
              └ export statement assigns a value to a key name that looks like a secret
```

With no arguments, `jit scan` scans your whole home directory, not your current
directory. A full sample of the output is in the
**[example report](./example-report.md)** (synthetic data).

## Scanning specific files or folders

Pass one or more paths to scan only those, instead of the whole machine:

```console
$ jit scan ./my-project token.txt
```

- A **folder** is walked with the same name-based rules as the full scan
  (`.env` files, IaC variable files, MCP configs, suspicious filenames), and
  skips the usual noise directories (`node_modules`, `.git`, …).
- A **file you name** is classified regardless of what it's called. A
  shell/`.env`/MCP/IaC file is routed to its scanner; a private key is detected
  by its contents; and anything else is swept for known vendor tokens and JWTs.
  That last part is why `jit scan token.txt` catches a bare token that the
  whole-machine scan's naming rules would never look at.

Named paths never pull in the fixed machine-wide credential stores (`~/.aws`,
`~/.ssh`, your shell configs) unless you name them, and symlinks are not
followed. A path that doesn't exist is an error, not a silently empty scan.

## Output formats

| Invocation | Gets you |
|---|---|
| `jit scan` | the human-readable report above |
| `jit scan --format markdown` | the same report as markdown, for saving or sharing |
| `jit scan --format ndjson` | one JSON record per finding plus a closing summary, for piping into other tools ([schema](../reference/audit-ndjson.md)) |
| `jit scan -o report.md` | write the report to a file instead of stdout |

## What happens next

Each finding category maps to a fix:

- Most categories are fixed by **[`jit migrate`](../migrate/index.md)** -
  it converts findings via each tool's native mechanism.
- **Wrappable CLI Tokens** findings are fixed by
  **[`jit wrap <tool>`](../wrap/index.md)** - audit prints the exact
  one-command fix next to each.
- **Private Keys**, **IaC Variable Files**, and **Suspicious Filenames**
  are surfaced for your judgment; there's no automatic migration for them.

The full category list is in **[What audit looks for](./findings.md)**.

`audit` and `migrate` are deliberately separate commands: a read-only
scanner can never be turned into a mutating one by a mistyped flag.
