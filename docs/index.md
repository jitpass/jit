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
jit scan                  # what's exposed on this machine? (strictly read-only)
jit migrate ~/code/myapp   # fix a file or project it found; tools keep working
jit wrap gh                # move a CLI's token into the vault; keep typing `gh` as before
jit run -- npm run dev     # or inject secrets straight into a process, no file at all
```

New here? Start with **[Why jit](./why-jit.md)** for the benefits in one page,
then **[Install](./getting-started/install.md)** →
**[Quickstart](./getting-started/quickstart.md)** →
**[How it works](./getting-started/how-it-works.md)** →
**[How it all fits together](./getting-started/how-it-fits.md)** (the mental model in one page) →
**[Delivering a secret](./getting-started/delivering-secrets.md)** (which command to use, and when).

## Get started

- [Install](./getting-started/install.md) - prebuilt binary or build from source, shell completion, upgrading
- [Quickstart](./getting-started/quickstart.md) - scan → vault → migrate → status, start to finish
- [How it works](./getting-started/how-it-works.md) - the vault, the service, mounts, shims, and provenance
- [How it all fits together](./getting-started/how-it-fits.md) - the three delivery models, and how integrating (migrate/wrap) and running (native hook, shim, or `jit run`) connect
- [Delivering a secret to a program](./getting-started/delivering-secrets.md) - when to use `jit wrap`, `jit run`, `jit run --profile`, and `read_as_file`
- [Troubleshooting](./getting-started/troubleshooting.md) - placeholder values, hangs, surprise Touch ID prompts
- [FAQ for developers and security](./faq.md) - blunt answers on how it works, what it protects, and what it deliberately does not

## Find exposed secrets - `jit scan`

- [Running an audit](./audit/index.md) - strictly read-only, output formats, saving reports, scanning specific files or folders
- [What audit looks for](./audit/findings.md) - every finding category explained
- [Example report](./audit/example-report.md) - what the output looks like (synthetic)

## Fix them - `jit migrate`

- [Migrating a project or a single file](./migrate/index.md) - name what to convert, dry runs, safety model
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
  [hf](./wrap/hf.md) · [supabase](./wrap/supabase.md) ·
  [openai](./wrap/openai.md) · [claude](./wrap/claude-code.md) ·
  [gemini](./wrap/gemini.md) · [codex](./wrap/codex.md) ·
  [aws](./wrap/aws.md) · [terraform](./wrap/terraform.md) ·
  [docker](./wrap/docker.md)
- [Custom tools](./wrap/custom-tools.md) - wrap anything that reads an env var
- [Wrap troubleshooting](./wrap/troubleshooting.md) - `wrap list`, `wrap doctor`, `wrap undo`

## Use secrets - `jit run` & profiles

- [Which command delivers a secret](./getting-started/delivering-secrets.md) - when to use `jit wrap`, `jit run`, `jit run --profile`, and `read_as_file`
- [Run a command with secrets](./run/index.md) - layer merging, modes, `--profile`, the compatibility swap and `--live`
- [Profiles](./run/profiles.md) - the manifest mapping variables to vault paths
- [Shell exports](./run/export.md) - `eval "$(jit export)"`
- [Live-mounted files](./run/mounts.md) - decoys, grants, the compatibility swap, and reading values safely

## The vault

- [Store, read, and delete secrets](./vault/index.md) - `set`/`get`/`list`/`rm`, rotating a key, undoing a rotation with `history`/`restore`
- [Back up and restore](./vault/backup-restore.md) - passphrase-encrypted export/import
- [Maintenance](./vault/maintenance.md) - `rekey`, `prune`, `clean`, `delete`

## The background service

- [Unlock once, not per command](./service/index.md) - always-on, TTL, lock/unlock
- [Provenance](./service/provenance.md) - why every prompt names its caller, `status` and `audit`

## Reference

- [Command reference](./reference/commands/jit.md) - every command and flag (generated, never drifts)
- [File locations](./reference/file-locations.md) · [Environment variables](./reference/environment-variables.md)
- [Audit NDJSON output](./reference/audit-ndjson.md) · [Plumbing protocols](./reference/plumbing.md)

## Security

- [Architecture](./security/architecture.md) - encryption, the service boundary, what jit does not protect against
- [Security brief](./security/brief.md) - a one-page summary for a security reviewer
- [Self-reviews](./security/self-reviews/index.md) - jit reviews its own code and publishes the results
- [Reporting a vulnerability](./security/reporting.md)

## Blog

- [jit blog](./blog/index.md) - the threat lens (infostealers, supply-chain attacks, where tools store your tokens) and inside jit (architecture, features, rationale)

## About

- [Contributing](./about/contributing.md) · [License (BUSL-1.1)](./about/license.md) · [Tech stack](./about/tech-stack.md)
