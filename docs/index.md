---
title: jit documentation
description: Just-in-time credentials for your dev machine - find plaintext secrets, vault them, and keep every tool working.
---

# jit documentation

**Just-in-time credentials for your dev machine.** jit finds the plaintext
secrets scattered across your machine (`.env` files, shell exports,
`~/.aws/credentials`, CLI tokens), moves them into a local encrypted vault,
and rewrites each consuming file so everything keeps working - with secrets
materializing only at the moment of use.

```sh
jit audit                  # what's exposed on this machine? (strictly read-only)
jit migrate local          # fix this project; tools keep working
jit wrap gh                # move a CLI's token into the vault; keep typing `gh` as before
jit run -- npm run dev     # or inject secrets straight into a process, no file at all
```

New here? **[Install](./getting-started/install.md)** →
**[Quickstart](./getting-started/quickstart.md)** →
**[How it works](./getting-started/how-it-works.md)**.

## Get started

- [Install](./getting-started/install.md) - prebuilt binary or build from source, shell completion, upgrading
- [Quickstart](./getting-started/quickstart.md) - audit → vault → agent → migrate, start to finish
- [How it works](./getting-started/how-it-works.md) - the vault, the agent, mounts, shims, and provenance
- [Troubleshooting](./getting-started/troubleshooting.md) - placeholder values, hangs, surprise Touch ID prompts

## Find exposed secrets - `jit audit`

- [Running an audit](./audit/index.md) - strictly read-only, output formats, saving reports
- [What audit looks for](./audit/findings.md) - every finding category explained
- [Example report](./audit/example-report.md) - what the output looks like (synthetic)

## Fix them - `jit migrate`

- [Migrating a project or your whole machine](./migrate/index.md) - `local` vs `home`, dry runs, safety model
- Per-credential guides: [.env files](./migrate/env-files.md) ·
  [shell configs](./migrate/shell-configs.md) · [AWS](./migrate/aws.md) ·
  [Kubernetes](./migrate/kubernetes.md) · [Terraform](./migrate/terraform.md) ·
  [GCP](./migrate/gcp.md) · [npm](./migrate/npm.md) · [MCP / AI tools](./migrate/mcp.md)
- [Undo, unmount, and remove](./migrate/undo-and-remove.md) - every change is reversible

## Wrap CLI tools - `jit wrap`

- [How wrapping works](./wrap/index.md) - PATH shims vs native credential hooks
- Supported tools: [gh](./wrap/gh.md) · [glab](./wrap/glab.md) ·
  [stripe](./wrap/stripe.md) · [ngrok](./wrap/ngrok.md) ·
  [doctl](./wrap/doctl.md) · [hcloud](./wrap/hcloud.md) ·
  [flyctl](./wrap/flyctl.md) · [vercel](./wrap/vercel.md) ·
  [railway](./wrap/railway.md) · [databricks](./wrap/databricks.md) ·
  [openai](./wrap/openai.md) · [aws](./wrap/aws.md) ·
  [terraform](./wrap/terraform.md)
- [Custom tools](./wrap/custom-tools.md) - wrap anything that reads an env var
- [Wrap troubleshooting](./wrap/troubleshooting.md) - `wrap list`, `wrap doctor`, `wrap undo`

## Use secrets - `jit run` & profiles

- [Run a command with secrets](./run/index.md) - layer merging, modes, `--profile`
- [Profiles](./run/profiles.md) - the manifest mapping variables to vault paths
- [Shell exports](./run/export.md) - `eval "$(jit export)"`
- [Live-mounted files](./run/mounts.md) - decoys, reveal windows, and reading values safely

## The vault

- [Store, read, and delete secrets](./vault/index.md) - `set`/`get`/`list`/`rm`, rotating a key, undoing a rotation with `history`/`restore`
- [Back up and restore](./vault/backup-restore.md) - passphrase-encrypted export/import
- [Maintenance](./vault/maintenance.md) - `rekey`, `prune`, `clean`, `delete`

## The background agent

- [Unlock once, not per command](./agent/index.md) - install, TTL, lock/unlock
- [Provenance](./agent/provenance.md) - why every prompt names its caller, `status` and `history`

## Reference

- [Command reference](./reference/commands/jit.md) - every command and flag (generated, never drifts)
- [File locations](./reference/file-locations.md) · [Environment variables](./reference/environment-variables.md)
- [Audit NDJSON output](./reference/audit-ndjson.md) · [Plumbing protocols](./reference/plumbing.md)

## Security

- [Architecture](./security/architecture.md) - encryption, the agent boundary, what jit does not protect against
- [Self-reviews](./security/self-reviews/index.md) - jit reviews its own code and publishes the results
- [Reporting a vulnerability](./security/reporting.md)

## Blog

- [jit blog](./blog/index.md) - the threat lens (infostealers, supply-chain attacks, where tools store your tokens) and inside jit (architecture, features, rationale)

## About

- [Contributing](./about/contributing.md) · [License (BUSL-1.1)](./about/license.md) · [Tech stack](./about/tech-stack.md)
