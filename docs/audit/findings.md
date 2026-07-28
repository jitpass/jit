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
| **Credential Files** | `~/.aws/credentials`, `~/.kube/config`, `.npmrc` auth tokens, the crates.io publish token in `~/.cargo/credentials.toml`, PyPI upload tokens and private-index passwords in `~/.pypirc`, the Terraform Cloud token file, Docker registry logins in `~/.docker/config.json`, git HTTPS logins in `~/.git-credentials`, GCP application-default credentials, `~/.netrc` passwords, Streamlit's `.streamlit/secrets.toml`, and remote-MCP OAuth refresh tokens under `~/.mcp-auth` | [`jit migrate`](../migrate/index.md) - except `~/.mcp-auth`, see below |
| **AI Tool / MCP Configs** | MCP server configs (project `mcp.json`, Claude Desktop config) with secrets in their env blocks | [`jit migrate`](../migrate/mcp.md) |
| **Private Keys** | on-disk private key material | surfaced for your judgment |
| **IaC Variable Files** | Terraform tfvars files, and Kubernetes Secret manifests (`*secret*.yaml` with `kind: Secret`) whose `data:` values are base64-**decoded** before judging - base64 is encoding, not encryption. Cluster-exported secrets and TLS/SSH/registry/basic-auth types escalate; SealedSecrets and fully SOPS-encrypted files are recognized as protected and skipped | tfvars: [`jit migrate`](../migrate/index.md); Secret manifests: surfaced for your judgment |
| **Wrappable CLI Tokens** | plaintext tokens in the config files of CLIs the [wrap catalog](../wrap/index.md) knows how to fix (`gh`, `stripe`, `ngrok`, …) | [`jit wrap <tool>`](../wrap/index.md) - audit prints the exact command |
| **SOPS Age Keys** | the age private key file (`keys.txt`) that decrypts every SOPS-encrypted secret it guards - sops, kluctl, Flux, helm-secrets | [`jit migrate`](../migrate/sops.md) |
| **Exposed Secrets** | a known vendor token or JWT found by **content**, whatever the file is called (`token.txt`, a random dump). Produced two ways: any file you name to `jit scan <path>`, and - on a whole-machine scan - files whose own NAME says they hold credentials (`*credentials*.csv` as downloaded from the AWS console, `jwt-secret.txt`, `api_key.json`). The name only decides what gets read; a finding still needs a vendor-format match in the content, so a crypto researcher's `tokens.csv` produces nothing | [`jit migrate <path>`](../migrate/index.md): the whole file vault-and-neutralizes to a pointer; a token embedded in a larger file needs `--mount` to protect it in place as a live mount |

Detection and migration share the same extractors: when a new tool enters
the wrap catalog, `jit scan` starts flagging its token automatically.

## What jit reports but cannot fix

Two things are reported for your judgment rather than with a fix command,
and the report says so rather than offering a `jit migrate` that would do
nothing:

- **Private keys.** Key material is surfaced with its passphrase and
  permission status; moving it is your call.
- **Remote-MCP OAuth tokens** (`~/.mcp-auth`). `mcp-remote` rotates and
  rewrites these files itself - access tokens last minutes, refresh tokens
  are re-issued on every use - so a vault-backed mount would be overwritten
  by the tool and serve values that had already rotated away. The fix is to
  revoke at the provider and reset with `rm -rf ~/.mcp-auth`, which is
  mcp-remote's own documented reset. Only the refresh token is reported: an
  access token is very likely dead before you read the report.

## Values with no vendor prefix

Most real credentials carry no recognizable prefix - CrowdStrike, Datadog,
Heroku, and every internal company API issue opaque strings. Those are caught
by a third signal: a long, credential-shaped value in a `.env` file is
reported even when nothing about its NAME says secret, at Medium confidence
because shape alone is weaker evidence than a vendor format.

Two things are deliberately given up to keep it honest:

- **Pure hex** (`a00c30f2f45f48b4ae3b0d0b151ac745`). Indistinguishable from a
  commit SHA, an MD5, or a correlation ID - the same reason bare 32/64-char
  hex has never been matched by the vendor patterns.
- **Names that announce an opaque non-secret**: `BUILD_SHA`, `GIT_COMMIT`,
  `APP_VERSION`, `REQUEST_ID`, `IMAGE_DIGEST`.

## What jit deliberately does not flag

The name heuristic is broad on purpose, so these are excluded to keep the
report worth reading. In every case the **value** is still checked
independently - a real credential hiding behind one of these is still
reported, and reported harder:

- **Browser-public build variables**: `VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`,
  `EXPO_PUBLIC_`, `GATSBY_`, and friends. The bundler inlines these into
  client JavaScript at build time, so they are public by construction -
  Vite's own docs say they "should not contain sensitive information". A
  name containing `SECRET`/`PASSWORD`/`PRIVATE` overrides this:
  `NEXT_PUBLIC_STRIPE_SECRET_KEY` is a misconfiguration, not a safe key.
- **Documented-public values**: Supabase `anon`/publishable keys, OAuth
  client IDs, analytics application IDs. (Datadog browser client tokens are
  covered too, via the build prefix they always carry.)
- **Paths, not secrets**: `*_PATH`, `*_FILE`, `*_DIR`. `SSH_KEY_PATH`
  holds a filename; the key it points at is covered by Private Keys.
- **Settings**: booleans, plain numbers (ports, timeouts, sample rates),
  and endpoint URLs carrying no credentials.
- **Unfilled template values**: `API_TOKEN=your-token-here` in a real
  `.env` you copied but haven't filled in. A human-chosen password that
  merely contains such a word (`Wherever2024!`) is still reported.

### Seeing what was filtered

Every one of those is a judgment call, and normally you can't see it being
made - which means you can't tell "jit found nothing" apart from "jit found
things and decided not to mention them". `--unfiltered` turns the gates off:

```sh
jit scan --unfiltered
jit scan --unfiltered --format ndjson > loud.ndjson   # diff against a normal run
```

Expect it to be noisy - that noise is the whole reason the filters exist.
It's for auditing what they hide, not for daily use.

One thing it deliberately does **not** turn off: rejection of filler token
bodies (`ghp_xxxxxxxx…`, a scrubbed `hf_FIXTUREtoken…`). That check is shared
with [`jit migrate`](../migrate/index.md), which must never vault a
placeholder as if it were a credential, so the two would disagree about what
is real.

## Risk level

The report rolls findings up into a single `RISK LEVEL` for the machine,
and each finding is individually rated. Findings that look like
*production* credentials or reference public IPs are called out - those
are counted separately in the [NDJSON summary
record](../reference/audit-ndjson.md) so downstream tooling can alert on
them specifically.
