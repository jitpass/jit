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
| **Credential Files** | `~/.aws/credentials`, `~/.kube/config`, `.npmrc` auth tokens, the crates.io publish token in `~/.cargo/credentials.toml`, PyPI upload tokens and private-index passwords in `~/.pypirc`, the Terraform Cloud token file, Docker registry logins in `~/.docker/config.json`, git HTTPS logins in `~/.git-credentials`, GCP application-default credentials, `~/.netrc` passwords, Streamlit's `.streamlit/secrets.toml`, remote-MCP OAuth refresh tokens under `~/.mcp-auth`, and the OneLogin API `client-secret` in clisso's `~/.clisso.yaml` | [`jit migrate`](../migrate/index.md) - except `~/.mcp-auth`, see below, and `~/.clisso.yaml`, which [`jit wrap clisso`](../wrap/clisso.md) handles |
| **AI Tool / MCP Configs** | MCP server configs (project `mcp.json`, Claude Desktop config, Claude Code's `~/.claude.json` including its per-project servers) and every way a server entry carries a credential: the `env` block, a plaintext file named by `--env-file`, a token baked into `args` (including `docker run -e KEY=value`), and a remote server's `headers` or `url` | [`jit migrate`](../migrate/mcp.md) for env blocks and `--env-file` targets; args/headers/url are surfaced for your judgment, see below |
| **Private Keys** | on-disk private key material. A PEM header alone is not enough - a key needs a **body**, established either by parsing the block (so an encrypted RSA key's `Proc-Type`/`DEK-Info` lines still count) or by a base64 run right after the header (the escaped-newline shape a GCP service-account JSON uses). So a file that merely *names* `-----BEGIN … PRIVATE KEY-----` - documentation, a test fixture, a scanner's own pattern list - is not flagged | surfaced for your judgment; a Google Cloud service-account key gets a definite instruction instead, see below |
| **IaC Variable Files** | Terraform tfvars files, and Kubernetes Secret manifests (`*secret*.yaml` with `kind: Secret`) whose `data:` values are base64-**decoded** before judging - base64 is encoding, not encryption. Cluster-exported secrets and TLS/SSH/registry/basic-auth types escalate; SealedSecrets and fully SOPS-encrypted files are recognized as protected and skipped | tfvars: [`jit migrate`](../migrate/index.md); Secret manifests: surfaced for your judgment |
| **Wrappable CLI Tokens** | plaintext tokens in the config files of CLIs the [wrap catalog](../wrap/index.md) knows how to fix (`gh`, `stripe`, `ngrok`, …) | [`jit wrap <tool>`](../wrap/index.md) - audit prints the exact command |
| **SOPS Age Keys** | the age private key file (`keys.txt`) that decrypts every SOPS-encrypted secret it guards - sops, kluctl, Flux, helm-secrets | [`jit migrate`](../migrate/sops.md) |
| **Exposed Secrets** | a known vendor token or JWT found by **content**, whatever the file is called (`token.txt`, a random dump). Produced two ways: any file you name to `jit scan <path>`, and - on a whole-machine scan - files whose own NAME says they hold credentials (`*credentials*.csv` as downloaded from the AWS console, `jwt-secret.txt`, `api_key.json`). The name only decides what gets read; a finding still needs a vendor-format match in the content, so a crypto researcher's `tokens.csv` produces nothing | [`jit migrate <path>`](../migrate/index.md): the whole file vault-and-neutralizes to a pointer; a token embedded in a larger file needs `--mount` to protect it in place as a live mount |
| **Shell History** | vendor-format credentials recorded in `~/.zsh_history`, `~/.bash_history`, `~/.sh_history`, `~/.history`, fish history, and whatever `$HISTFILE` points at. This is the surface every other category misses by construction: a credential gets here by being **typed**, so it is never in a file whose name or location announces it. A password written as a shell expansion (`postgres://app:$PGPASSWORD@…`) is not a finding - nothing is exposed by it | [`jit migrate <historyfile>`](../migrate/shell-history.md): each credential moves to the vault and every occurrence is redacted in place, command lines intact. A production-flagged one stays manual (rotate). [`jit guard history`](../migrate/shell-history.md#stopping-the-next-one) stops the next one being recorded |

Detection and migration share the same extractors: when a new tool enters
the wrap catalog, `jit scan` starts flagging its token automatically.

One block of scan output is deliberately **not** in this table. Credentials
other tools mint for themselves - the STS session the AWS CLI caches, the
tokens `aws sso login` writes, the session clisso caches in
`~/.aws/credentials-cache` - are reported under "Outside jit's scope, found
anyway", and they never become findings: no `finding_type`, no severity, no
place in any count. They are named so a clean report cannot be misread as an
empty directory, not because jit intends to do anything about them. Don't go
looking for a finding type here that will never exist.

## What jit reports but cannot fix

Some things are reported for your judgment rather than with a fix command,
and the report says so rather than offering a `jit migrate` that would do
nothing:

- **Private keys.** Key material is surfaced with its passphrase and
  permission status; moving it is your call. The exception is a Google Cloud
  service-account key, which the report names as what it is and files under
  "rotate in IAM, then delete the file": it has no passphrase to add, and
  deleting the file does not revoke it - only deleting the key in IAM does.
- **Self-rotating token caches** (`~/.mcp-auth`, `~/.gemini/oauth_creds.json`).
  The owning tool rotates and rewrites these files itself - access tokens
  last minutes, refresh tokens are re-issued on every use - so a vault-backed
  mount would be overwritten by the tool and serve values that had already
  rotated away. The fix is to revoke at the provider and let the tool
  re-authenticate; for `~/.mcp-auth` that is `rm -rf ~/.mcp-auth`,
  mcp-remote's own documented reset. Only the refresh token is reported: an
  access token is very likely dead before you read the report.
- **Credentials a remote MCP server sends itself.** A `type: http`/`sse`
  server entry with an `Authorization` header, or a token in its `url`, is
  reported but not migratable: the MCP *host* makes that HTTP request, so
  there is no process for jit to inject into and no rewrite that would help.
  The same goes for a token baked into a server's `args`, where it is also
  visible to `ps` for every process running as you: pulling one argument out
  of a command line has no safe general rule (the flag may be positional,
  repeated, or required). Move the token to the provider's OAuth flow where
  one exists, or rotate it out of the file.
- **Terraform state** (`terraform.tfstate`). State records every attribute
  Terraform wrote, secrets included, in plaintext - HashiCorp documents this.
  Terraform writes the file itself, so there is no seam for jit to serve it
  from the vault. The fix is to rotate what leaked, move state to an
  encrypted remote backend, and keep secrets out of it with ephemeral values
  (Terraform 1.10+). jit scans these files only because nothing else would:
  the name carries no credential word, so the content sweep would walk past.
- **Production-flagged credentials in shell history.** An ordinary history
  credential is migratable: `jit migrate ~/.zsh_history` vaults each value
  and redacts every occurrence in place, leaving a `<jit:redacted:VAR>`
  marker where the secret was (the command line itself survives; `jit vault
  get` recovers the value; `jit migrate undo` restores the file whole). A
  credential carrying a production indicator stays in this manual bucket:
  clearing the recorded copy does not un-expose a production credential, so
  rotation is the fix and the report refuses to offer a command as if it
  were. Two truths hold either way, and the migrate output repeats them -
  the value has already been written to disk (history files get backed up by
  Time Machine and committed to dotfile repos as a matter of routine), and
  zsh and bash hold history in memory and rewrite the file on exit, so a
  line redacted while another session is open can come back. Run `fc -R` in
  each open zsh (`history -r` in bash) or close them, then re-run `jit scan`
  to confirm; a re-run of migrate re-redacts a resurrected line into the
  same vault entry.

  Private key material typed at the prompt is reported here too, as
  **critical**, and is the one history finding `jit migrate` will not redact:
  jit matches the `-----BEGIN` header, so removing it would leave the key body
  behind and make the file look clean. Regenerate the key instead.

  Prevention exists too: `jit guard history` installs a zsh hook that checks
  each command for a known credential format before zsh writes it to the
  history file - a flagged command stays usable in that session (up-arrow
  works) but is never recorded, so the next pasted token has nothing to be
  found in.

  A secret found in a *production-flagged* history line **and** in a file
  `jit migrate` can protect is counted once, and is not counted as
  migratable: vaulting the config copy leaves that history copy readable, so
  your coverage moves when you rotate, not when you migrate. The migrate is
  still worth running, and the report says so.

Test fixtures - a `*_test.go`, anything under `testdata/` - are reported but
never counted toward your coverage score. The value matches a real credential
format because that is exactly what a scanner's own fixtures are written to
do; there is simply no owner and nothing to rotate.

Source examples are the same rule's third face: a vendor-format match on a
comment line of a source-code file - a scanner's own pattern list, a doc
comment arguing about credential shapes by example - documents a shape rather
than storing a secret. The footer counts them ("N source examples") instead
of charging them to the score. The accepted miss: a commented-out *real*
credential in source lands in the same bucket, which is why the bucket is
named rather than silently dropped - it stays visible in `jit scan --full`.
Shell scripts are deliberately outside this rule; a commented-out
`# export TOKEN=…` is exactly the shape a real leak takes, so it stays
counted.

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
- **Shell expansions in a connection string**: the password in
  `postgres://app:$PGPASSWORD@db/app` (or `${VAR}`, `$(op read …)`, a
  backtick) is a reference, not a value - the secret lives wherever the
  expansion reads it from. This matters most in shell history, where writing
  it that way is how you avoid the exposure in the first place. A literal
  password in the same shape is still reported.

### Seeing what was filtered

Every one of those is a judgment call, and normally you can't see it being
made - which means you can't tell "jit found nothing" apart from "jit found
things and decided not to mention them". `--unfiltered` turns the gates off:

```sh
jit scan --unfiltered
jit scan --unfiltered --format ndjson > loud.ndjson
```

Expect it to be noisy - that noise is the whole reason the filters exist.
It's for auditing what they hide, not for daily use. You don't need to diff
two runs to see the gates' work: every finding the everyday scan would hide
or downgrade is tagged `[unfiltered]` in the report (and carries
`unfiltered_only`/`unfiltered_reason` in NDJSON, schema 0.15.0+), with a
`└ shown by --unfiltered: …` line naming the exact rule that hid it.

One thing it deliberately does **not** turn off: rejection of filler token
bodies (`ghp_xxxxxxxx…`, a scrubbed `hf_FIXTUREtoken…`). That check is shared
with [`jit migrate`](../migrate/index.md), which must never vault a
placeholder as if it were a credential, so the two would disagree about what
is real.

## Risk level

The full report (`jit scan --full`, and any targeted `jit scan <path>`)
rolls findings up into a single risk level for the machine (the report's
`✗ CRITICAL — exposure 100/100` banner), and each
finding is individually rated. The default machine-wide view reports
coverage instead - how many secrets are protected and what protects the
rest - and never shows severity labels. Findings that look like
*production* credentials or reference public IPs are called out - those
are counted separately in the [NDJSON summary
record](../reference/scan-ndjson.md) so downstream tooling can alert on
them specifically.
