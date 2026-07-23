---
title: What audit looks for
description: Every jit scan finding category, and which command fixes it.
---

# What audit looks for

Every finding lands in one of these categories. Each carries a severity,
a masked value preview, and a one-line *why* explaining what matched.

| Category | What it scans | The fix |
|---|---|---|
| **Shell Configs** | `~/.zshrc`, `~/.bashrc`, profile files - `export KEY=value` lines whose key name or value shape looks like a secret | [`jit migrate`](../migrate/shell-configs.md) |
| **.env Files** | project `.env`-family files whose values match known token formats or secret-shaped entropy | [`jit migrate`](../migrate/env-files.md) |
| **Credential Files** | `~/.aws/credentials`, `~/.kube/config`, `.npmrc` auth tokens, the Terraform Cloud token file, Docker registry logins in `~/.docker/config.json`, git HTTPS logins in `~/.git-credentials`, GCP application-default credentials, `~/.netrc` passwords | [`jit migrate`](../migrate/index.md) |
| **AI Tool / MCP Configs** | MCP server configs (project `mcp.json`, Claude Desktop config) with secrets in their env blocks | [`jit migrate`](../migrate/mcp.md) |
| **Private Keys** | on-disk private key material | surfaced for your judgment |
| **IaC Variable Files** | Terraform tfvars files, and Kubernetes Secret manifests (`*secret*.yaml` with `kind: Secret`) whose `data:` values are base64-**decoded** before judging - base64 is encoding, not encryption. Cluster-exported secrets and TLS/SSH/registry/basic-auth types escalate; SealedSecrets and fully SOPS-encrypted files are recognized as protected and skipped | tfvars: [`jit migrate`](../migrate/index.md); Secret manifests: surfaced for your judgment |
| **Suspicious Filenames** | files whose names suggest stashed secrets (`secrets.txt` and friends) | surfaced for your judgment |
| **Wrappable CLI Tokens** | plaintext tokens in the config files of CLIs the [wrap catalog](../wrap/index.md) knows how to fix (`gh`, `stripe`, `ngrok`, …) | [`jit wrap <tool>`](../wrap/index.md) - audit prints the exact command |
| **SOPS Age Keys** | the age private key file (`keys.txt`) that decrypts every SOPS-encrypted secret it guards - sops, kluctl, Flux, helm-secrets | [`jit migrate`](../migrate/sops.md) |
| **Exposed Secrets** | a known vendor token or JWT found by **content** in a file you name explicitly to `jit scan <path>`, whatever the file is called (`token.txt`, a random dump). Only produced by a targeted scan of named paths, never the whole-machine walk | surfaced for your judgment |

Detection and migration share the same extractors: when a new tool enters
the wrap catalog, `jit scan` starts flagging its token automatically.

## Risk level

The report rolls findings up into a single `RISK LEVEL` for the machine,
and each finding is individually rated. Findings that look like
*production* credentials or reference public IPs are called out - those
are counted separately in the [NDJSON summary
record](../reference/audit-ndjson.md) so downstream tooling can alert on
them specifically.
