# Feature: `jit wrap` — shell-plugin-style CLI wrapping

`jit wrap <tool>` gives developers transparent, vault-backed credentials
for the CLIs they already run: they keep typing `gh pr list` exactly as
before, but the GitHub token no longer lives in plaintext on disk — it
sits encrypted in the vault and materializes only inside the one process
that needs it, gated by the same biometric agent every other jit flow uses.

**Shipped in v0.8.0 (2026-07-14).** Supported tools:
[PLUGINS.md](./PLUGINS.md); command reference: [COMMANDS.md](./COMMANDS.md);
spike evidence: `spike/cli-shim-wrap/FINDINGS.md`.

This document is the feature's reference and its design record. A few
places where the shipped feature went beyond the original design:

- The catalog grew past the table in §3.2: hcloud, flyctl, vercel,
  railway, and databricks are covered too (a `json` extractor joined
  yaml/toml; `.databrickscfg`'s INI rides the toml line extractor).
- Discovery has a `TokenCommand` fallback: tools that keep their token in
  the OS keyring (modern gh) export it via their own documented command;
  nothing is scrubbed in that case.
- §3.6's overlay rule (project env layers over the wrap profile) is not
  implemented yet — the shim uses plain `--profile` semantics. Still open,
  alongside multi-account profiles and agent-history attribution for wrap
  invocations.
- `jit wrap undo` of a scrubbed file points at `jit migrate undo <path>`
  for the byte-for-byte restore rather than doing it inline.

## 1. What this is

Shell-plugin-style CLI wrapping, built on jit's existing vault, agent, and
profiles: a developer runs one command —

```
$ jit wrap gh
```

— and from then on they keep typing `gh pr list` exactly as before, but the
GitHub token no longer exists in `~/.config/gh/hosts.yml`. It lives encrypted
in the vault and materializes only inside each `gh` process, gated by the
same unlocked-agent / Touch ID session every other jit flow uses.

jit already has the hard parts: per-process injection (`jit run` execve's
into the target), the biometric-gated agent, profiles, encrypted backups,
undo. What's missing is exactly three things:

1. **A catalog** — knowing that `gh` reads `GH_TOKEN` and stores its
   plaintext token in `hosts.yml`.
2. **Transparent invocation** — the developer types `gh`, not
   `jit run --profile wrap-gh -- gh`.
3. **Discovery** — `jit audit` telling the developer their gh token is
   sitting on disk and that `jit wrap gh` fixes it.

## 2. Why this makes developers' lives easier

**Before:** a gh/stripe/ngrok/doctl token lives in a plaintext dotfile,
readable by every process running as the user, swept into Time Machine and
Spotlight, alive years after it was pasted. The "secure" alternative is
retyping tokens or hand-rolling credential-injecting aliases that silently
stop working inside scripts.

**After `jit wrap gh`:**

- Nothing about muscle memory changes — `gh`, scripts calling `gh`,
  Makefiles, git hooks, other tools spawning `gh` all keep working
  (spike Result 1: shims cover the invocation paths aliases can't).
- The token is on disk only as an individually encrypted vault entry;
  in memory only inside the one process that needs it, for its lifetime.
- First use per session shows jit's attributed prompt ("unlock the vault
  for profile *wrap-gh*, launched by *make*"), then it's silent —
  once per session, not once per command.
- ~17 ms added per invocation with an unlocked agent (spike Result 3) —
  imperceptible for human-driven CLIs.
- `jit wrap undo gh` puts the original file back byte-for-byte, because
  every mutated file was backed up encrypted first, like every migrate.

## 3. Design

### 3.1 The shim mechanism (validated by the spike)

A shim directory, `~/.jit/shims/`, placed at the front of `PATH`. Each
wrapped CLI gets an entry named after itself. When invoked, the shim:

1. Derives the tool name from `argv[0]`.
2. Aborts (`exit 127`) if `JIT_SHIM_GUARD_<TOOL>` is set — belt-and-braces
   recursion guard.
3. Finds the *real* binary by walking `PATH`, skipping the shim directory
   (compare against the known `~/.jit/shims` location, resolved through
   `EvalSymlinks`; the spike confirmed symlinked duplicate PATH entries
   don't defeat the skip).
4. `execve`s `jit run --profile wrap-<tool> -- <real> <args…>`. Arguments,
   exit codes, stdio, signals all propagate untouched (spike Result 2).

**Shim entries are symlinks to the jit binary, dispatched on `argv[0]`**
(busybox-style): `cmd/jit/main.go` checks `filepath.Base(os.Args[0])`; if
it isn't `jit`, it enters shim mode. This avoids copying a multi-MB binary
per tool (the spike used a standalone binary only for isolation). If
`argv[0]` dispatch proves fragile for some exec path, the fallback is a
single tiny `jit-shim` helper binary hardlinked per tool — decided in M1.

Failure behavior is deliberately loud: real binary missing → named error
on stderr, exit 127, never a loop, never a silent unwrapped run.

### 3.2 The catalog (`internal/wrap`)

A compiled-in table, one entry per supported CLI:

```go
type CatalogEntry struct {
    Tool        string            // "gh"
    Kind        Kind              // KindShim (env-var injection via shim) or
                                  // KindNative (delegate to an existing migrate
                                  // flow that hooks the tool's own credential
                                  // mechanism — aws, terraform)
    EnvVars     map[string]string // env var -> vault subpath: {"GH_TOKEN": "token"}
    Sources     []TokenSource     // where the plaintext lives today + how to extract
    ScrubMode   ScrubMode         // delete value / delete file / rewrite without field
    VerifyHint  string            // e.g. "gh auth status" — printed after wrap
}

type TokenSource struct {
    Path    string // "~/.config/gh/hosts.yml"
    Format  string // yaml | json | ini | keyvalue
    Extract string // format-specific selector, e.g. "github.com.oauth_token"
}
```

Compiled-in (not user-editable files) for v1: entries are code-reviewed
data, and `jit audit`'s detection must agree with `wrap`'s extraction, so
they ship together. The catalog grows by developer-tool popularity. Initial
set, chosen for token-in-plaintext-file pain:

| Tool | Kind | Mechanism | Plaintext source today |
| --- | --- | --- | --- |
| `gh` | shim | `GH_TOKEN` | `~/.config/gh/hosts.yml` |
| `glab` | shim | `GITLAB_TOKEN` | `~/.config/glab-cli/config.yml` |
| `stripe` | shim | `STRIPE_API_KEY` | `~/.config/stripe/config.toml` |
| `ngrok` | shim | `NGROK_AUTHTOKEN` | `~/Library/Application Support/ngrok/ngrok.yml` |
| `doctl` | shim | `DIGITALOCEAN_ACCESS_TOKEN` | `~/Library/Application Support/doctl/config.yaml` |
| `hcloud` | shim | `HCLOUD_TOKEN` | `~/.config/hcloud/cli.toml` |
| `openai` | shim | `OPENAI_API_KEY` | env/shell config (no file) |
| `aws` | native | existing `credential_process` migrate flow | `~/.aws/credentials` |
| `terraform` | native | existing `credentials_helper` migrate flow | `~/.terraform.d/credentials.tfrc.json` |

(Exact paths/selectors verified per tool during M2 — each catalog entry
lands with a fixture test against a real sample of that tool's file.)

**Native entries: `jit wrap aws` and `jit wrap terraform` are catalog
members but don't install shims.** jit already hooks these tools through
their own credential mechanisms, and those hooks are *stronger* than an
env-var shim: `credential_process` feeds not just the `aws` CLI but every
AWS SDK (boto3, the Go SDK, Terraform's AWS provider — processes a PATH
shim never sees), and the `credentials_helper` keeps `terraform
login`/`logout` working. Downgrading them to shims would shrink coverage.
So a `KindNative` entry makes `jit wrap <tool>` delegate to the existing
migrate flow — one uniform verb for the developer ("wrap any CLI in the
catalog"), the best mechanism per tool underneath. They appear in `jit
wrap list` alongside shim entries, with their mechanism named, and `jit
wrap undo aws` routes to the corresponding migrate undo.

(A shim-based fallback for `aws` via `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`
was considered and rejected: it would cover only direct CLI invocations
and would fight the `credential_process` hook if both were active.)

An escape hatch for uncataloged tools ships in M1:

```
$ jit wrap add mycli --env MY_TOKEN=path/in/vault
```

— no discovery or scrubbing, just profile + shim. This also decouples the
mechanism from catalog growth.

### 3.3 Command surface

```
jit wrap <tool>            # catalog flow: discover token, vault it, profile, shim, scrub, verify
jit wrap add <tool> --env VAR=vaultpath [...]   # manual flow, any tool
jit wrap list              # wrapped tools, profile, shim health, PATH position
jit wrap undo <tool>       # remove shim+profile, restore original file from encrypted backup
jit wrap doctor            # shim dir on PATH? first? every shim's real binary resolvable? profiles resolve?
```

`jit wrap <tool>` step by step:

1. Look up the catalog entry; refuse with pointers if unknown
   (`jit wrap add` mentioned in the error).
2. Locate the real CLI on PATH — if absent, stop ("install gh first").
3. Extract the token from its source file; if none found, offer paste-in
   (`jit vault set` semantics, no echo).
4. `vault set wrap-gh/GH_TOKEN` (namespace `wrap-<tool>/`), encrypted
   backup of the source file first — reusing migrate's backup tracker,
   so `undo` is byte-for-byte.
5. Write global profile `~/.jit/profiles/wrap-gh.yaml`
   (global scope for the same reason shell/MCP migrations are: the shim
   can be invoked from any cwd).
6. Symlink `~/.jit/shims/gh → <jit binary>`.
7. Ensure `~/.jit/shims` is first on PATH: reuse migrate's shell-config
   editing (`scriptsedit.go`) to add one line to the rc file, once —
   `export PATH="$HOME/.jit/shims:$PATH"` — with the user shown the exact
   edit before it happens.
8. Scrub the token from the source file per `ScrubMode` (the file itself
   often carries non-secret config that must survive — same discipline as
   the npmrc rewriter).
9. Run the catalog's verify hint (`gh auth status`) through the shim and
   show the result.

### 3.4 Audit integration

`internal/audit` gains a `wrappable-cli-token` signal: for each catalog
entry, if the source file exists and the extractor finds a live-looking
token, report it with the fix inline:

```
~/.config/gh/hosts.yml
  github.com oauth_token — GitHub CLI token, plaintext        [high]
  fix: jit wrap gh
```

Audit stays strictly read-only; it shares the catalog's `TokenSource`
extractors so detection and migration can't drift apart. This is the
discovery loop: audit names the problem *and* the one-command fix.

### 3.5 Security considerations

- **Shim dir trust:** `~/.jit/shims` created 0700; `wrap doctor` warns if
  permissions loosen or if another writable-by-others dir precedes it on
  PATH.
- **PATH-order honesty:** the shim only narrows exposure; a malicious
  entry earlier in PATH could already impersonate any binary. Wrapping
  adds no new trust beyond what PATH implies — state this in docs.
- **Attribution:** the agent prompt shows profile + launching process
  lineage (existing `internal/lineage`), so "unlock for *wrap-gh*,
  launched by *some-curl-pipe-script*" gives the user a real decision.
- **Subprocess inheritance:** the injected env var is inherited by the
  wrapped tool's children — same property `jit run` already has;
  documented, not new.
- **No silent fallback:** a shim that can't find the real tool or jit
  fails loudly (127) rather than degrading to an unwrapped run.

### 3.6 Interaction with `jit migrate local`/`home`

Wrap and migrate solve different halves and never compete for the same
secret: migrate local owns *project-scoped* secrets (`.env` values that
differ per repo, consumed by the app), wrap owns *machine-global* CLI
tokens (one gh token in one config file, valid from any cwd). Audit
routes each finding to the right verb.

They do meet at runtime: a wrapped CLI invoked inside a migrated
project. Example: `stripe` is wrapped globally (personal test key), and
this project's migrated `.env` also defines `STRIPE_API_KEY`. Plain
`jit run --profile` semantics would ignore the project layers (`--profile`
disables merging), silently injecting the global key — wrong for the
developer standing in that project.

**Rule: the wrap profile is a base layer; project env layers overlay it**
(`profile.Overlay(wrap-<tool>, project layers…)`, later wins — the same
precedence philosophy as `.env` < `.env.local`). Global token everywhere
by default; a migrated project that defines the same variable wins inside
that project. Implemented as a shim-mode resolution path, leaving
`jit run --profile`'s documented no-merge behavior untouched. Unlike
`jit run`, the shim does not print a merge announcement on every
invocation (that would make every `gh` call noisy); `jit wrap list` and
`doctor` show the effective layering instead.

### 3.7 Explicitly out of scope (v1)

- **New native hooks**: `KindNative` catalog entries (aws, terraform)
  only *delegate* to hook flows migrate already ships. Building new
  tool-specific hooks (e.g. a kubectl entry delegating to the exec
  credential plugin flow) is follow-on catalog work, not v1 scope.
- **Config-file-only tools with no existing hook and no env var**: not
  wrappable by either kind; served by live-mounts if at all.
- **Flag-based injection** (`--token` argv rewriting): argv is visible in
  `ps`; needs its own design if ever.
- **Windows/Linux**: follows jit's macOS-only status.
- **Per-invocation approval mode** ("prompt every time for stripe
  production keys"): natural follow-on, needs agent policy work first.

## 4. Code structure and conventions

The feature follows the repo's existing discipline — small single-concern
files, each with a sibling `_test.go`, a `doc.go` stating the package's
charter, nothing near the ~600-line ceiling the largest current files sit
at, and `internal/cli` holding thin per-verb wiring only. Concretely:

```
cmd/jit/main.go              argv[0] dispatch only — a few lines deciding
                             "am I jit or a shim?", then delegating

internal/wrap/
  doc.go                     package charter: what wrap owns, what it reuses
  catalog.go                 CatalogEntry/TokenSource types + lookup; NO I/O,
                             NO tool entries
  catalog_data.go            the tool entries themselves — pure data, one
                             block per tool, reviewed like data
  extract.go                 Extractor interface + format registry
  extract_yaml.go            one file per format, each with fixture tests
  extract_toml.go            against real samples in testdata/<tool>/
  extract_ini.go
  scrub.go                   rewrite a source file minus its secret,
                             preserving everything non-secret
  shim.go                    the exec path: PATH walk + skip, guard, execve
                             (port of the spike's main.go)
  native.go                  KindNative delegation — routes wrap/undo for
                             aws/terraform to migrate's existing flows;
                             no credential logic of its own
  install.go                 shim dir + symlink lifecycle
  pathenv.go                 the one PATH rc line (delegates to
                             migrate's scriptsedit, no duplicate editor)
  manifest.go                wrapped-tool bookkeeping (what's wrapped,
                             which backup restores it)
  doctor.go                  health checks consumed by `wrap doctor`/`list`
  undo.go                    restore flow, built on migrate's backup tracker

internal/cli/
  wrap.go                    cobra wiring for wrap/add/list/undo/doctor —
                             flag parsing and output formatting only,
                             mirroring audit.go/migrate.go altitude

internal/audit/
  wrapcli.go                 the wrappable-cli-token signal — imports
                             wrap's catalog + extractors so detection and
                             migration literally share code and can't drift
```

Rules that keep it maintainable as the catalog grows:

- **Every file has a sibling test** (`extract_yaml.go` ↔
  `extract_yaml_test.go`), table-driven where the repo already does that;
  each catalog tool lands with a `testdata/<tool>/` fixture copied from a
  real (sanitized) config file — adding a tool touches `catalog_data.go`
  and a fixture directory, nothing else.
- **Data and logic never share a file**: `catalog_data.go` contains zero
  branching; extractors contain zero tool names.
- **One direction of dependency**: `cli → wrap → (vault, profile,
  migrate-backup, lineage)`; `audit → wrap` for the shared extractors;
  `wrap` never imports `cli` or `audit`.
- **The shim path stays minimal**: `shim.go` may import only stdlib —
  it runs on every wrapped invocation, so no config parsing, no YAML,
  no vault code before the `execve`.
- **No grab-bag files**: nothing named `util.go`/`helpers.go`; a helper
  lives in the file of its single caller until a second caller exists.

## 5. How it shipped (milestones)

All four milestones landed for v0.8.0. They're recorded here in delivery
order as the feature's build history.

**M1 — mechanism (small, no catalog):** `argv[0]` dispatch in `cmd/jit`,
shim-mode exec path (port of the spike's `main.go` with its guards),
`jit wrap add/list/undo` for manual entries, shim install + PATH rc edit.
Files: `shim.go`, `install.go`, `pathenv.go`, `manifest.go`, `undo.go`,
`cli/wrap.go` — the catalog/extract/scrub files don't exist yet.
Tests: unit (PATH skip, guard, symlink resolution) + an integration test
that builds a fake tool and asserts injection/exit-code/args through the
real binary, essentially automating the spike.

**M2 — catalog + audit (the product):** `internal/wrap` catalog with the
first ~5 shim tools plus the `KindNative` delegations for `aws` and
`terraform` (thin routing to the existing migrate flows and their undo),
extractor + scrub per format (yaml/toml/ini), fixture tests from real
config samples, encrypted-backup + `undo` parity with migrate, audit's
`wrappable-cli-token` findings, `jit wrap doctor`.

**M3 — polish:** COMMANDS.md/USAGE.md/README coverage table row, verify
hints, `wrap list` health output, shell-completion sanity check through
shims (expected to just work — command names are unchanged), latency note
in docs with the spike's numbers.

**M4 — expansion:** grow the catalog (ordered by dev-tool popularity),
multi-account support
(profile-per-account, `jit wrap gh --account work` → `wrap-gh-work`),
possibly project-scoped wrap profiles.

Sequencing note: M1 is deliberately shippable alone — `jit wrap add`
already covers any tool a motivated user has — so catalog breadth never
blocks the mechanism landing.

## 6. Design questions and how they resolved

1. `argv[0]` symlink dispatch vs. dedicated shim binary — **resolved:**
   `argv[0]` dispatch, shim entries symlinked to the jit binary (§3.1).
   The skip logic never depended on it, since the shim dir path is known
   config.
2. Does `wrap` share migrate's pointer-file/lineage bookkeeping or keep
   its own manifest? **Resolved:** reuse migrate's backup tracker, with a
   separate manifest for shims.
3. Rotation story: `jit wrap refresh gh` re-extracts after the user runs
   `gh auth login` again (which recreates the plaintext file). **Still
   open** — a follow-up, not in v0.8.0.
4. Should `jit migrate home` auto-suggest wraps for detected catalog
   tools, or stay a separate explicit verb? **Resolved:** audit suggests
   (§3.4), never auto-wraps.

## 7. Spike evidence (summary)

From `spike/cli-shim-wrap/FINDINGS.md` (2026-07-14, macOS arm64, real
`jit run` + unlocked agent):

- Aliases silently skip injection in scripts and execvp spawns; shims
  inject in every path tested. → shims.
- Recursion fully controlled: PATH-skip + env guard; clean 127s, correct
  exit-code propagation (42 → 42).
- Overhead: 8.9 ms baseline vs 26.3 ms full pipeline ≈ **+17 ms** per
  invocation, warm agent — imperceptible interactively.
