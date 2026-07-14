# Example: what `jit audit` finds

This is **real output** from `WriteHumanReport` (`internal/audit/report.go`), run against a throwaway fixture `$HOME` built inside a Go test — not hand-typed. (One hand-applied delta since generation: the `Wrappable CLI Tokens` summary line, which the renderer now always prints — the fixture predates that category and has no such finding, so `0 finding(s)` is exactly what a regeneration would produce.) Every path, username, and value below is fabricated (fake keys, fake tokens, a disposable ed25519 key generated just for this run) and was never a real credential. The fixture and the test that produced this file are not checked in; regenerate by writing a short `_test.go` in `internal/audit` that builds a fixture directory tree, calls `Scan`/`WriteHumanReport` against it, and deletes itself afterward — see the commit that introduced this version of the doc for the exact fixture used.

Keeping this generated from the real renderer, rather than hand-maintained, is the whole point: a mockup that silently drifts from actual output is worse than no example at all — that's what happened to the previous version of this file, which predated the renderer's real key/value/why-labeled format entirely.

---

```
jit audit — risk report for alex@Alexs-MacBook-Pro
scan time: 2026-07-06T09:14:22.000Z          duration: 340ms

  RISK LEVEL: CRITICAL
  (1 production-indicator/public-IP match(es) found)
    - /Users/alex/code/webapp/.env

  Shell Configs          2 finding(s)
  .env Files             4 finding(s)
  Credential Files       4 finding(s)
  AI Tool / MCP Configs  4 finding(s)
  Private Keys           2 finding(s)
  IaC Variable Files     1 finding(s)
  Suspicious Filenames   1 finding(s)
  Wrappable CLI Tokens   0 finding(s)
  ───────────────────────────────────
  Total: 18 finding(s)
  Already protected by jit: 2 live mount(s) — served from the encrypted vault, no plaintext on disk. Not scanned.

[Shell Configs]
  /Users/alex/.zshrc
    :2  [high]  key: STRIPE_API_KEY
        value:  sk_l**********
        why:    value matches Stripe Live Secret Key's known token format
    :3  [high]  key: DB_PASSWORD
        value:  hunt**********
        why:    export statement assigns a value to a key name that looks like a secret

[.env Files]
  /Users/alex/code/webapp/.env
    [critical]
        why:    contains a value matching the production-indicator pattern
  same pattern in 2 files:
    [high]
        why:    contains "JAMF_URL", a variable name that looks like a real credential
          - /Users/alex/code/tool-a/.env
          - /Users/alex/code/tool-b/.env
  /Users/alex/code/api-service/.env
    [low]
        why:    2 variable(s) in this file (2 active, 0 commented out) — either way, the values are stored here in plaintext

[Credential Files]
  /Users/alex/.aws/credentials
    [high]  key: dev/aws_secret_access_key
        value:  fake**********
        why:    AWS secret access key found in profile "dev"
    [high]  key: staging/aws_secret_access_key
        value:  fake**********
        why:    AWS secret access key found in profile "staging"
  /Users/alex/.config/gcloud/application_default_credentials.json
    [high]  key: refresh_token
        value:  1//f**********
        why:    GCP application default credentials (authorized_user) found
  /Users/alex/.terraform.d/credentials.tfrc.json
    [high]  key: app.terraform.io
        value:  fake**********
        why:    Terraform Cloud API token found for host "app.terraform.io"

[AI Tool / MCP Configs]
  internal-tool/GITHUB_TOKEN — same value in 2 files:
    [high]  key: internal-tool/GITHUB_TOKEN
        value:  ghp_**********
        why:    embedded directly in MCP server "internal-tool"'s env block
          - /Users/alex/.cursor/mcp.json
          - /Users/alex/code/webapp/.mcp.json
  internal-tool/CAIDO_URL — same value in 2 files:
    [low]  key: internal-tool/CAIDO_URL
        value:  http**********
        why:    plain URL in MCP server "internal-tool"'s env block — likely just an endpoint, but URLs can embed secrets too (e.g. webhook tokens)
          - /Users/alex/.cursor/mcp.json
          - /Users/alex/code/webapp/.mcp.json

[Private Keys]
  /Users/alex/.ssh/id_ed25519
    [high]
        why:    no passphrase set
  /Users/alex/Downloads/old-server-access.pem
    [high]
        why:    private key found outside ~/.ssh; no passphrase set

[IaC Variable Files]
  /Users/alex/code/infra/k8s/secrets.yaml
    [info]
        why:    infrastructure-as-code variable file — detection only, no automated fix yet

[Suspicious Filenames]
  /Users/alex/Downloads/1Password Emergency Kit A3-XXXXXX-example.pdf
    [medium]
        why:    1Password Emergency Kit — contains the account's master and secret key if genuine

Run `jit migrate local --dry-run` (or `jit migrate home --dry-run`) to see the guided fix plan for what's fixable here.
No secret values are ever printed in full. Run `jit audit --format ndjson` for machine-readable output (same redaction rules apply).
```

## What made this Critical

A **production-indicator match** — `/Users/alex/code/webapp/.env` contains a value matching the production-indicator pattern (a `PROD_DATABASE_URL`-shaped connection string). This is the only thing that escalated this scan to Critical; a public IP address in a visible value triggers the same escalation but isn't present in this fixture.

The risk banner lists the triggering file path directly (`- /Users/alex/code/webapp/.env`) rather than just saying "see below" — with dozens of findings spread across several categories on a real machine, a bare "see below" cost a full read of the report to resolve into an actual file to go fix.

## Why severity order matters within a category

Every finding within a category is sorted worst-severity-first (file path as tiebreak), not alphabetically by path. On a real machine with dozens of findings in one category, sorting by path alone buried the findings that actually justified the top-level risk banner behind a wall of lower-severity ones that happened to sort earlier alphabetically.

## Why some findings collapse into one block

`/Users/alex/code/tool-a/.env` and `/Users/alex/code/tool-b/.env` both contain the exact same secret-shaped variable name (`JAMF_URL`) — same severity, same explanation. Rather than repeat an identical `[high]`/`why:` block twice, they collapse into one block with both paths listed underneath, under its own header line (`same pattern in 2 files:`) rather than a file path. Same for the MCP `GITHUB_TOKEN`/`CAIDO_URL` findings (headers there also name the key, e.g. `internal-tool/GITHUB_TOKEN — same value in 2 files:`), embedded identically in two separate configs. Real-world dogfooding on a machine with dozens of findings turned this up constantly — the same MCP server's credentials copy-pasted into 3+ config files, the same secret-shaped variable name across 7+ unrelated `.env` files — and repeating the identical explanation once per file was the single biggest source of clutter in a dense report.

A collapsed block's header line matters, not just its content: an earlier version of this rendered a collapsed block with no header at all, directly beneath the previous item's file path — a real user found this genuinely ambiguous, since it read as if that block's findings belonged to the file printed just above it, when they were actually an unrelated pattern shared by different files entirely. Every block — per-file or collapsed — now starts with its own unambiguous header line for exactly this reason.

This only collapses when the match is genuinely meaningful (severity + key name + evidence + masked value all identical): two files sharing the same variable name but a *different* actual value never collapse, and a handful of categories (IaC's unescalated tier, Suspicious Filenames) never collapse at all, since their evidence is fixed rule-level text that says nothing about a specific file's content — two unrelated files matching the same rule aren't actually related, and collapsing them would wrongly imply they are.

## What's *not* shown here, on purpose

- No real value ever appears in full — everything is either a short masked preview (`sk_l**********`) or, for file-level findings like `.env`'s low-severity case, no value at all.
- `jit audit` never writes or modifies anything, under any flag — this is exactly what got scanned, not what got "fixed." Fixing findings is a separate command, `jit migrate`, so the read-only audit tool can't be turned into a mutating one by a mistyped flag.
