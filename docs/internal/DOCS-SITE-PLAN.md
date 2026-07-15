# Docs Site Plan

Design for restructuring `docs/` into a publishable documentation site (GitHub Pages
or any static-docs platform), modeled on the 1Password Developer docs information
architecture.

## 1. Goals

- One folder tree of plain Markdown + frontmatter that any generator (Starlight,
  MkDocs Material, Mintlify, Docusaurus) can build — the content never gets locked
  to a platform.
- Mirror how users actually move through jit: **find secrets → fix them → live with
  the runtime**, the same way 1Password splits "Develop locally / Deploy securely".
- Per-tool pages for `jit wrap`, exactly like 1Password's shell-plugin pages
  (`/cli/shell-plugins/gh/`), so each tool page can rank in search and be linked
  from the tool's community.
- Command reference generated from cobra (never drifts from `--help`).
- `llms.txt` index generated at build time, like `1password.dev/llms.txt`.

## 2. Feature → section map

jit's surface, grouped into the site's top navigation:

| Nav section | Covers |
|---|---|
| **Get Started** | what jit is, install, quickstart, mental model (vault / agent / shims / mounts) |
| **Audit** | `jit audit`, every finding category, example report, NDJSON output |
| **Migrate** | `jit migrate local/home/undo/remove`; per-credential pages: AWS, Kubernetes, Terraform, npm, shell configs, `.env` live mounts, MCP/AI-tool configs |
| **Wrap** | shim vs native model; one page per catalog tool (13); `wrap add` for custom tools; `wrap doctor/list/undo` |
| **Run & Profiles** | `jit run`, `jit export`, profile manifests, live mounts + `agent reveal`, `unmount` |
| **Vault** | `vault init/set/get/list/rm`, backup & restore (`export`/`import`), maintenance (`clean`/`prune`/`delete`) |
| **Agent** | why the agent exists, `install/uninstall`, `unlock/lock`, TTL, `history` (provenance), `status` |
| **Reference** | full command reference (generated), file locations, environment variables, NDJSON schema, plumbing protocols (`aws-credential-process`, `k8s-exec-credential`, `terraform-credentials`) |
| **Security** | threat model & architecture, self-review reports, vulnerability reporting |
| **About** | contributing, license (BUSL-1.1), tech stack |

## 3. Folder tree

```
docs/
├── index.md                          # Landing: "Stop keeping secrets in plaintext" — hero + section cards
├── getting-started/
│   ├── install.md                    # prebuilt binary, build from source, completions, upgrading
│   ├── quickstart.md                 # audit → migrate → run in 5 minutes
│   ├── how-it-works.md               # vault, agent, shims, mounts — the mental model diagram
│   └── faq.md
├── audit/
│   ├── index.md                      # running an audit, output formats (text/md/ndjson)
│   ├── findings.md                   # every scanner category explained + risk levels
│   └── example-report.md             # (from example-audit-report.md)
├── migrate/
│   ├── index.md                      # local vs home, --dry-run, --only, safety model (encrypted backups)
│   ├── aws.md                        # credential_process rewrite; covers SDKs too
│   ├── kubernetes.md                 # ExecCredential plugin
│   ├── terraform.md                  # credentials_helper
│   ├── npm.md                        # .npmrc
│   ├── shell-configs.md              # .zshrc / .bashrc exports
│   ├── env-files.md                  # .env → live mounts, reveal hooks (.envrc, npm scripts)
│   ├── mcp.md                        # Claude Desktop / editor MCP configs via jit run
│   └── undo-and-remove.md            # migrate undo, migrate remove, backups & prune
├── wrap/
│   ├── index.md                      # concept, shim vs native, tool card grid (the PLUGINS.md content)
│   ├── gh.md  glab.md  ngrok.md  doctl.md  stripe.md  hcloud.md
│   ├── flyctl.md  vercel.md  railway.md  databricks.md  openai.md
│   ├── aws.md  terraform.md          # native-hook pages (thin: link into migrate/)
│   ├── custom-tools.md               # jit wrap add --env for uncataloged tools
│   └── troubleshooting.md            # wrap doctor / list / undo, shim + PATH issues
├── run/
│   ├── index.md                      # jit run --profile --mode
│   ├── profiles.md                   # manifests, .jit/profiles/, profile list/show, doctor
│   ├── export.md                     # shell exports, eval "$(jit export)"
│   └── mounts.md                     # live .env mounts, agent reveal --for, unmount
├── vault/
│   ├── index.md                      # init, set/get/list/rm, --stdin, clipboard
│   ├── backup-restore.md             # vault export/import (passphrase file)
│   └── maintenance.md                # clean, prune, delete
├── agent/
│   ├── index.md                      # why unlock-once; Touch ID/passcode; TTL
│   ├── install.md                    # launchd install/uninstall, agent run foreground
│   └── provenance.md                 # caller identification, agent history, agent status
├── reference/
│   ├── commands/                     # GENERATED from cobra — one page per command
│   │   └── (jit.md, jit_audit.md, jit_wrap.md, …)
│   ├── file-locations.md             # ~/Library/Application Support/jitpass/, ~/.jit/shims, .jit/profiles/
│   ├── environment-variables.md      # JIT_SHIM_GUARD_*, injected vars per tool
│   ├── audit-ndjson.md               # NDJSON schema (v0.3.0)
│   └── plumbing.md                   # aws-credential-process, k8s-exec-credential, terraform-credentials
├── security/
│   ├── architecture.md               # threat model, envelope encryption, Keychain/Secure Enclave, peercred
│   ├── self-reviews/
│   │   └── 2026-07.md                # (from security/2026-07-review.md; future reviews land here)
│   └── reporting.md                  # (from SECURITY.md)
├── about/
│   ├── contributing.md               # thin page linking to CONTRIBUTING.md
│   ├── license.md                    # BUSL-1.1 explained
│   └── tech-stack.md                 # (from TECH_STACK.md, trimmed for readers)
└── internal/                         # NOT published — excluded from the site build
    ├── WRAP-PLAN.md                  # design docs stay in-repo but out of the site
    └── DOCS-SITE-PLAN.md             # this file
```

Repo-root files (`README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`) stay
where they are — GitHub renders them; the site pages link to or summarize them.
`spike/` stays out of the site entirely.

## 4. Existing content → new home

| Today | Becomes |
|---|---|
| `docs/USAGE.md` | split: `getting-started/quickstart.md`, `getting-started/install.md`, `run/*`, `agent/*`, per-section troubleshooting |
| `docs/COMMANDS.md` | replaced by generated `reference/commands/` |
| `docs/PLUGINS.md` | `wrap/index.md` + seeded per-tool pages |
| `docs/example-audit-report.md` | `audit/example-report.md` |
| `docs/WRAP-PLAN.md` | `docs/internal/` (unpublished) |
| `README.md` | source for `index.md` + `getting-started/how-it-works.md`; README itself slims down and links to the site |
| `TECH_STACK.md` | `about/tech-stack.md` |
| `security/*.md` | `security/` section |

## 5. Per-tool wrap page template

Every `wrap/<tool>.md` follows one skeleton (same discipline as 1Password's
shell-plugin pages — uniform, scannable, one tool per page):

```markdown
---
title: Wrap <tool> with jit
description: Keep your <TOKEN_VAR> out of <plaintext path> — injected just-in-time.
---
# <tool>

<one-line: what credential it stores, where, and what jit does about it>

## Requirements        # jit installed, vault init, agent running, tool version
## Wrap it             # jit wrap <tool> — what it discovers, vaults, scrubs
## Verify              # the catalog VerifyHint (e.g. `gh auth status`)
## How it works        # env var injected, source file scrubbed, shim path
## Undo                # jit wrap undo <tool>
## Troubleshooting     # tool-specific gotchas
```

The catalog in `internal/wrap/catalog_data.go` already holds tool, env var, source
path, and verify hint — the first draft of all 13 pages can be generated from it.

## 6. Platform recommendation

Content is generator-agnostic; the recommended build:

- **Astro Starlight** — closest to the 1Password look (cards, tabs, dark mode,
  built-in search via Pagefind, i18n later), pure static output, first-class
  GitHub Pages deploy action. Site scaffolding lives in `website/` at repo root,
  consuming `docs/` as its content dir, so the Go module stays clean.
- Lighter alternative: **MkDocs Material** (Python, one YAML file, `mkdocs gh-deploy`).
  Same tree works unchanged.
- Both are free and self-hosted on GitHub Pages; Mintlify (what 1Password uses)
  is the hosted option if a managed platform is ever preferred.

## 7. Automation

- **`jit docs-gen` (hidden cobra command)** using `cobra/doc.GenMarkdownTree` →
  writes `docs/reference/commands/`. CI check fails if output is stale, so the
  reference can never drift from `--help`.
- **Wrap pages seeded from the catalog**: a small `go generate` tool renders the
  template in §5 from `catalog_data.go` for any tool missing a page (existing
  hand-edited pages are never overwritten).
- **`llms.txt`**: build step walks the published tree and emits title + one-line
  description per page, served at the site root.
- **Deploy**: GitHub Actions on push to `main` — build site, publish to Pages.

## 8. Milestones

- **D1 — Scaffold & deploy pipeline.** Site skeleton, GitHub Pages action, empty
  sections live at the public URL. Proves the pipeline before content moves.
- **D2 — Content migration.** Split USAGE/README/PLUGINS into the tree above;
  leave one-line pointer stubs in the old files for one release.
- **D3 — Generated reference.** `jit docs-gen`, CI staleness check, delete
  COMMANDS.md.
- **D4 — Wrap tool pages.** Catalog-driven generation + hand polish of the top
  tools (gh, aws, stripe, vercel).
- **D5 — Polish.** Landing page cards, search, llms.txt, security section.
