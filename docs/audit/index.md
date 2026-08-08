---
title: Running an audit
description: jit scan - a strictly read-only scan for plaintext secrets exposed on this machine.
---

# Running an audit - `jit scan`

`audit` answers one question: **is my machine clean?** It is strictly
read-only under every flag: it never touches, encrypts, or rewrites
anything, and never prints a real secret value in full, only a masked
preview.

It also says what it does *not* cover. Some credentials are written by other
tools for their own use — the plaintext STS session the AWS CLI caches in
`~/.aws/cli/cache`, the tokens `aws sso login` leaves in `~/.aws/sso/cache`,
the session [clisso](../wrap/clisso.md) caches in `~/.aws/credentials-cache`
and what it records in `~/.clisso.log` — and jit does not manage them. Those are reported under **"Outside jit's scope,
found anyway"**: advisory only, never findings, never counted in any total, and
with no effect on the risk level or the coverage ledger. They are hex-named, so
the content sweep would otherwise walk straight past them, and "no findings"
would quietly imply that the directory jit just tidied was empty.

```
jit scan  ~/ · 7 files · 1ms

  YOUR SECRETS: 7 — 0 protected by jit (0%)
  ▱▱▱▱▱▱▱▱▱▱  to 100%: one command +71% · 2 secrets only you can fix +29%

  jit will protect these — 5 secrets in 4 files, 0% → 71%
      → jit migrate
        one command; it vaults the values and rewrites 4 files — every tool that
        reads them keeps working:
        ~/.aws/credentials  default/aws_secret_access_key
        ~/.zshrc            STRIPE_API_KEY, DB_PASSWORD
        ~/code/webapp/.env  secret-shaped values
        ~/token.txt         JSON Web Token (JWT)
      these are in plaintext now — rotating after vaulting is the gold standard
      · every change is reversible: jit migrate undo

  only you can protect these — 2 secrets, 71% → 100%

    [rotate, then delete every copy]
    ! A production database password in 2 files
      ~/Downloads/customer-secrets-report.txt … and 1 more
      → rotate it now, then delete every copy

    [seal it]
    ! A Kubernetes Secret manifest with real values
      ~/infra/k8s/secrets.yaml
      → seal it (sealed-secrets/SOPS) or move it to a real secret store

  → jit scan --full   the full inventory · ndjson for machines

  No secret values are ever printed in full.
```

With no arguments, `jit scan` scans your whole home directory, not your current
directory, and reports **coverage**: how many distinct secrets exist on the
machine, how many jit already protects, and the shortest path to 100% - the
green section is exactly what bare [`jit migrate`](../migrate/index.md)
will do, and the red section is what only you can do. `jit scan --full`
prints the finding inventory instead: every category, severity, file and
line, rolled up into a risk level. A full sample of both views is in the
**[example report](./example-report.md)** (synthetic data).

## Scanning specific files or folders

Pass one or more paths to scan only those, instead of the whole machine:

```console
$ jit scan ./my-project token.txt
```

- A **folder** is walked with the same name-based rules as the full scan
  (`.env` files, IaC variable files, MCP configs), and
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
| `jit scan` | the coverage summary above (machine-wide default) |
| `jit scan --full` | the full finding inventory: categories, severities, every file and line, plus the machine risk level |
| `jit scan --format markdown` | the same report as markdown, for saving or sharing |
| `jit scan --format ndjson` | one JSON record per finding plus a closing summary, for piping into other tools ([schema](../reference/scan-ndjson.md)) |
| `jit scan -o report.md` | write the report to a file instead of stdout |

The "Outside jit's scope" advisory appears in the default view, in `--full`,
and in markdown. It is deliberately **not** in NDJSON: that schema describes
findings jit stands behind, and this is a note to a human.

## What happens next

The default view already made the split: the green section is fixed by
running bare **[`jit migrate`](../migrate/index.md)** (which also runs
any **[`jit wrap <tool>`](../wrap/index.md)** the plan calls for), and
the red section lists what only you can do - rotate, delete, or seal.
Per category, in the `--full` inventory:

- Most categories are fixed by **`jit migrate`** - it converts findings
  via each tool's native mechanism.
- **Wrappable CLI Tokens** findings are fixed by **`jit wrap <tool>`** -
  the report prints the exact one-command fix next to each, and bare
  `jit migrate` runs them for you.
- **Shell History** findings are fixed by **`jit migrate <historyfile>`**,
  which vaults each credential and redacts every occurrence in place. One
  exception: a history credential carrying a production indicator stays in
  the red section, because clearing the recorded copy does not un-expose a
  production secret - rotation does. `jit guard history` keeps the next one
  from being recorded at all.
- **Private Keys** and most **IaC Variable Files** are surfaced for your
  judgment; there's no automatic migration for them. One key kind does get a
  definite instruction: a Google Cloud service-account key is filed under
  "rotate in IAM, then delete the file", because a passphrase cannot be added
  to one and deleting the file does not revoke it.

The full category list is in **[What audit looks for](./findings.md)**.

`audit` and `migrate` are deliberately separate commands: a read-only
scanner can never be turned into a mutating one by a mistyped flag.
