# Example: what `jit scan` finds

This is **real output** from `WriteHumanReport` (`internal/audit/report.go`), run against a throwaway fixture `$HOME` built inside a Go test, not hand-typed. Every path, username, and value below is fabricated (fake keys, fake tokens, a disposable ed25519 key generated just for this run) and was never a real credential. The fixture includes two registered live jit mounts (the "Already protected" line). The fixture and the test that produced this file are not checked in; regenerate by writing a short `_test.go` in `internal/audit` that builds a fixture directory tree, calls `Scan`/`WriteHumanReport` against it, and deletes itself afterward, see the commit that introduced this version of the doc for the exact fixture used.

Every category appears in the summary, at zero if nothing matched. **Exposed Secrets** is zero here and always will be in a whole-machine scan: that category only comes from naming a path yourself (`jit scan token.txt`), where a file is swept for vendor tokens whatever it is called.

Keeping this generated from the real renderer, rather than hand-maintained, is the whole point: a mockup that silently drifts from actual output is worse than no example at all.

---

```
jit scan: risk report for alex@Alexs-MacBook-Pro
scan time: 2026-07-25T16:37:55.518Z          duration: 1ms

  RISK LEVEL: CRITICAL
  EXPOSURE:   100/100
  (1 production-indicator/public-IP match(es) found)
    - /Users/alex/code/webapp/.env

  Shell Configs          2 finding(s)
  .env Files             4 finding(s)
  Credential Files       5 finding(s)
  AI Tool / MCP Configs  4 finding(s)
  Private Keys           2 finding(s)
  IaC Variable Files     1 finding(s)
  Wrappable CLI Tokens   1 finding(s)
  SOPS Age Keys          1 finding(s)
  Exposed Secrets        0 finding(s)
  ───────────────────────────────────
  Total: 20 finding(s)
  Already protected by jit: 2 live mount(s), served from the encrypted vault, no plaintext on disk. Not scanned.

[Shell Configs] 2
  • /Users/alex/.zshrc

    :2  HIGH  STRIPE_API_KEY  sk_l**********
              └ value matches Stripe Live Secret Key's known token format

    :3  HIGH  DB_PASSWORD     hunt**********
              └ export statement assigns a value to a key name that looks like a secret

[.env Files] 4
  • /Users/alex/code/webapp/.env

    CRITICAL  contains a value matching the production-indicator pattern

  • same pattern in 2 files:

    HIGH      contains "JAMF_URL", a variable name that looks like a real credential
              - /Users/alex/code/tool-a/.env
              - /Users/alex/code/tool-b/.env

  • /Users/alex/code/api-service/.env

    LOW       2 plaintext variable(s) (2 active, 0 commented out)

[Credential Files] 5
  • /Users/alex/.aws/credentials

    HIGH  dev/aws_secret_access_key      fake**********
          └ AWS secret access key found in profile "dev"

    HIGH  staging/aws_secret_access_key  fake**********
          └ AWS secret access key found in profile "staging"

  • /Users/alex/.cargo/credentials.toml

    HIGH  registry/token                 cio2**********
          └ cargo registry token found for crates.io; it can publish crates as you

  • /Users/alex/.config/gcloud/application_default_credentials.json

    HIGH  refresh_token                  1//f**********
          └ GCP application default credentials (authorized_user) found

  • /Users/alex/.terraform.d/credentials.tfrc.json

    HIGH  app.terraform.io               fake**********
          └ Terraform Cloud API token found for host "app.terraform.io"

[AI Tool / MCP Configs] 4
  • internal-tool/GITHUB_TOKEN (same value in 2 files):

    HIGH  internal-tool/GITHUB_TOKEN  ghp_**********
          └ embedded directly in MCP server "internal-tool"'s env block
          - /Users/alex/.cursor/mcp.json
          - /Users/alex/code/webapp/.mcp.json

  • internal-tool/CAIDO_URL (same value in 2 files):

    LOW   internal-tool/CAIDO_URL     http**********
          └ plain URL in MCP server "internal-tool"'s env block; URLs can embed tokens
          - /Users/alex/.cursor/mcp.json
          - /Users/alex/code/webapp/.mcp.json

[Private Keys] 2
  • /Users/alex/.ssh/id_ed25519

    HIGH  no passphrase set

  • /Users/alex/Downloads/old-server-access.pem

    HIGH  private key found outside ~/.ssh; no passphrase set

[IaC Variable Files] 1
  • /Users/alex/code/infra/k8s/secrets.yaml

    INFO  kubernetes Secret manifest (base64 is encoding, not encryption): detection only, no automated fix yet

[Wrappable CLI Tokens] 1
  • /Users/alex/.config/gh/hosts.yml

    HIGH  oauth_token  gho_**********
          └ GitHub CLI OAuth token in plaintext; one command moves it into the vault and keeps gh working: jit wrap gh

[SOPS Age Keys] 1
  • /Users/alex/.config/sops/age/keys.txt

    :3  HIGH  age_secret_key  AGE-**********
              └ SOPS age private key: decrypts every SOPS-encrypted secret this key guards (sops, kluctl, Flux, helm-secrets)

Run `jit migrate /Users/alex/.zshrc --dry-run` to see the guided fix plan for it.
No secret values are ever printed in full. Run `jit scan --format ndjson` for machine-readable output (same redaction rules apply).
```

## How to read a finding block

Each non-empty category opens with a bold header and its finding count (`[Credential Files] 5`). Within it, every block gets a `•`-marked header (a file path, or a pattern name for findings collapsed across files), and each finding is one aligned row: line number (when known), severity, key name, and masked value line up in columns, with the free-form reason hanging on its own `└` line beneath, where it can wrap on a narrow terminal without breaking the columns. Findings with neither a key nor a value (a plaintext `.env` file's presence, an unencrypted key) keep their reason inline next to the severity.

## What made this Critical

A **production-indicator match**, `/Users/alex/code/webapp/.env` contains a value matching the production-indicator pattern (a `PROD_DATABASE_URL`-shaped connection string). This is the only thing that escalated this scan to Critical; a public IP address in a visible value triggers the same escalation but isn't present in this fixture.

The risk banner lists the triggering file path directly (`- /Users/alex/code/webapp/.env`) rather than just saying "see below", with dozens of findings spread across several categories on a real machine, a bare "see below" cost a full read of the report to resolve into an actual file to go fix.

## Why severity order matters within a category

Every finding within a category is sorted worst-severity-first (file path as tiebreak), not alphabetically by path. On a real machine with dozens of findings in one category, sorting by path alone buried the findings that actually justified the top-level risk banner behind a wall of lower-severity ones that happened to sort earlier alphabetically.

## Why some findings collapse into one block

`/Users/alex/code/tool-a/.env` and `/Users/alex/code/tool-b/.env` both contain the exact same secret-shaped variable name (`JAMF_URL`), same severity, same explanation. Rather than repeat an identical row twice, they collapse into one block with both paths listed underneath, under its own header line (`same pattern in 2 files:`) rather than a file path. Same for the MCP `GITHUB_TOKEN`/`CAIDO_URL` findings (headers there also name the key, e.g. `internal-tool/GITHUB_TOKEN (same value in 2 files):`), embedded identically in two separate configs. Real-world dogfooding on a machine with dozens of findings turned this up constantly, the same MCP server's credentials copy-pasted into 3+ config files, the same secret-shaped variable name across 7+ unrelated `.env` files, and repeating the identical explanation once per file was the single biggest source of clutter in a dense report.

A collapsed block's header line matters, not just its content: an earlier version of this rendered a collapsed block with no header at all, directly beneath the previous item's file path, a real user found this genuinely ambiguous, since it read as if that block's findings belonged to the file printed just above it, when they were actually an unrelated pattern shared by different files entirely. Every block, per-file or collapsed, now starts with its own unambiguous header line for exactly this reason.

This only collapses when the match is genuinely meaningful (severity + key name + evidence + masked value all identical): two files sharing the same variable name but a *different* actual value never collapse, and one category (IaC's unescalated tier) never collapses at all, since its evidence is fixed rule-level text that says nothing about a specific file's content, two unrelated files matching the same rule aren't actually related, and collapsing them would wrongly imply they are.

## What's *not* shown here, on purpose

- No real value ever appears in full, everything is either a short masked preview (`sk_l**********`) or, for file-level findings like `.env`'s low-severity case, no value at all.
- `jit scan` never writes or modifies anything, under any flag, this is exactly what got scanned, not what got "fixed." Fixing findings is a separate command, `jit migrate`, so the read-only audit tool can't be turned into a mutating one by a mistyped flag.
