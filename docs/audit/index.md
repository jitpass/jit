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

`audit` always scans your whole home directory, not your current directory.
A full sample of the output is in the
**[example report](./example-report.md)** (synthetic data).

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
