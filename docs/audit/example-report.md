# Example: what `jit scan` prints

This is **real output** from both renderers (`WriteTriageReport` and
`WriteHumanReport`, `internal/audit/triage.go` / `report.go`), run against a
throwaway fixture `$HOME` built inside a Go test, not hand-typed. Every path,
username, and value below is fabricated (fake keys, fake tokens) and was never
a real credential. The fixture and the test that produced this file are not
checked in; regenerate by writing a short `_test.go` in `internal/audit` that
builds a fixture directory tree, calls `Scan` and both renderers against it,
and deletes itself afterward - see the commit that introduced this version of
the doc for the exact fixture used.

Keeping this generated from the real renderers, rather than hand-maintained,
is the whole point: a mockup that silently drifts from actual output is worse
than no example at all.

## The default view - `jit scan`

The machine-wide default reports **coverage**: how many distinct secrets
exist, how many jit protects, and the shortest path to 100%. Findings are
grouped into what bare `jit migrate` will do (the green manifest - every
file the command will rewrite, listed for consent) and what only you can do
(cause-grouped problems: copies of one file collapse into one item). No
categories, no severity labels - those live in `--full`, below.

```
jit scan — alex@Alexs-MacBook-Pro — scanned ~/ (7 files) — 3ms

  YOUR SECRETS: 7 — 0 protected by jit (0%)
  ▱▱▱▱▱▱▱▱▱▱  to 100%: one command +85% · 1 thing only you can fix +14%

  jit will protect these — 6 secrets in 5 files, 0% → 85%
      → jit migrate
        one command; it vaults the values and rewrites 5 files — every tool that
        reads them keeps working:
        ~/.aws/credentials        default/aws_secret_access_key
        ~/.zshrc                  STRIPE_API_KEY, DB_PASSWORD
        ~/code/webapp/.env        secret-shaped values
        ~/infra/k8s/secrets.yaml  secret-shaped values
        ~/token.txt               JSON Web Token (JWT)
      these sat in plaintext until now — rotating after vaulting is the gold
      standard · every change is reversible: jit migrate undo

  only you can protect these — 1 secret, 85% → 100%
    ! A production database password in 2 copies of a file  (1)
      ~/Downloads/customer-secrets-report.txt … and 1 more
      → rotate it now, then delete every copy

  → jit scan --full   the full inventory · ndjson for machines

  No secret values are ever printed in full.
```

Counting note: the two report copies hold the **same** database password, so
they are one secret of the 7, not two - the ledger counts distinct secrets,
never findings. Low/Info sightings are not counted at all; they are jit's own
uncertainty, listed only in `--full`.

## The full inventory - `jit scan --full`

The per-category inventory with severities, line numbers, and the machine
risk level. A targeted `jit scan <path>` prints this view by default - a scan
you aimed at one file is a request for its inventory.

```
jit scan — alex@Alexs-MacBook-Pro — scanned ~/ (7 files) — full inventory — 1ms

  ✗ CRITICAL — exposure 100/100
    2 production-indicator/public-IP matches — each file itemized in its
    category below
    e.g. ~/Downloads/customer-secrets-report.txt … and 1 more

  Shell Configs          2
  .env Files             1
  Credential Files       1
  AI Tool / MCP Configs  0
  Private Keys           0
  IaC Variable Files     1
  Wrappable CLI Tokens   0
  SOPS Age Keys          0
  Exposed Secrets        3
  ────────────────────────
  Total                  8

[Shell Configs] 2
  • ~/.zshrc

    :1  HIGH  STRIPE_API_KEY  sk_l**********
              └ value matches Stripe Live Secret Key's known token format

    :2  HIGH  DB_PASSWORD     hunt**********
              └ export statement assigns a value to a key name that looks like a
                secret

[.env Files] 1
  • ~/code/webapp/.env

    HIGH  contains a value matching OpenAI Project API Key's known token format

[Credential Files] 1
  • ~/.aws/credentials

    HIGH  default/aws_secret_access_key  Xk92**********
          └ AWS secret access key found in profile "default"

[IaC Variable Files] 1
  • ~/infra/k8s/secrets.yaml

    HIGH  kubernetes Secret manifest of type kubernetes.io/basic-auth: holds a
          username/password pair

[Exposed Secrets] 3
  • ~/Downloads/customer-secrets-report.txt

    :1  CRITICAL  Database connection string with embedded credentials (scheme-less)  svc_**********
                  └ value matches production-indicator pattern

  • ~/exports/customer-secrets-report.txt

    :1  CRITICAL  Database connection string with embedded credentials (scheme-less)  svc_**********
                  └ value matches production-indicator pattern

  • ~/token.txt

    :1  HIGH      JSON Web Token (JWT)                                                eyJh**********
                  └ value matches its known token format


  → jit migrate ~/.zshrc --dry-run   the guided fix plan for the first flagged
    file
  No secret values are ever printed in full · jit scan --format ndjson for
  machines, same redaction
```

Under `--unfiltered`, the same view adds an amber `○ suppression off` notice
at the top, tags each finding the everyday gates would have hidden with
`[unfiltered]`, and explains the rule that hid it on a
`└ shown by --unfiltered: …` line — so one report answers what the filters
are hiding, instead of needing a diff of two runs.

## How to read a finding block (`--full`)

Each non-empty category opens with a bracketed header and its dim finding
count (`[Shell Configs] 2`). Within it, every block gets a `•`-marked header (a
file path, or a pattern name for findings collapsed across files), and each
finding is one aligned row: line number (when known), severity, key name, and
masked value line up in columns, with the free-form reason hanging on its own
`└` line beneath, where it can wrap on a narrow terminal without breaking the
columns. Findings with neither a key nor a value keep their reason inline
next to the severity.

## What made this Critical

A **production-indicator match**: the copied report files contain a
connection string whose host says `prod`. This alone escalates the `--full`
risk level to Critical - and it is also exactly why the default view routes
that secret to "only you can protect these" with *rotate* as the action:
protecting a file in place does not un-expose a production credential that
sat in plaintext.

## Why severity order matters within a category

Every finding within a `--full` category is sorted worst-severity-first
(file path as tiebreak), not alphabetically by path. On a real machine with
dozens of findings in one category, sorting by path alone buried the findings
that actually justified the risk level behind a wall of lower-severity ones
that happened to sort earlier alphabetically.

Both views obey the same redaction rule: no secret value is ever printed in
full, in any format.
