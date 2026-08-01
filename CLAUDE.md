# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

There is no Makefile — CI (`.github/workflows/ci.yml`) is the canonical list, and it must pass on macOS with `CGO_ENABLED=1`.

```sh
go build ./...
go test -race -timeout 2m ./...                    # -timeout well under Go's 10m default: this
                                                   # suite blocks on FIFOs, sockets and open(2),
                                                   # so a hang is a real failure mode
go test -race -run TestName ./internal/vault/      # a single test
go test -race -run 'TestFoo/subtest' ./internal/cli/
```

Before pushing, the full gate CI applies:

```sh
gofmt -l ./cmd ./internal                          # must print nothing (spike/ is exempt)
go vet ./...
go mod verify && go mod tidy                       # go.mod/go.sum must not drift
staticcheck ./...                                  # honnef.co/go/tools/cmd/staticcheck@v0.7.0
govulncheck ./...                                  # golang.org/x/vuln/cmd/govulncheck@v1.6.0
gosec -exclude-generated ./...                     # github.com/securego/gosec/v2/cmd/gosec@v2.28.0
```

Tool versions are **pinned deliberately** — a floating `@latest` changes CI results under commits that touched none of it. Bump on purpose, not by accident.

**After changing any command's help text, flags, or adding a command:**

```sh
go run ./cmd/jit docs-gen                          # regenerates docs/reference/commands/
```

CI fails on drift, and checks with `git status --porcelain` rather than `git diff` — a new command produces an *untracked* page that `git diff` does not see.

Release-config changes:

```sh
goreleaser check
goreleaser release --snapshot --clean --skip=publish,sign,notarize,homebrew
```

## Architecture

`cmd/jit/main.go` is a thin entry point into `internal/cli`. Each subcommand registers itself onto `rootCmd` from its own file's `init()` (`scan.go`, `migrate.go`, `run.go`, `vault.go`, …); `root.go` holds only the root command and shared scaffolding. `internal/cli` is by far the largest package (~30k lines) — start from the file named after the command.

The design maps onto four pillars from the (private) RFC, and the package `doc.go` files are authoritative and unusually detailed — **read the `doc.go` before the code** in any `internal/` package.

**Storage and encryption.** `internal/vault` is atomic, file-per-secret storage with envelope encryption: each secret gets a random AES-256-GCM data key, wrapped by a caller-supplied `vault.KeyWrapper`. The package has no opinion on how the wrapping key is protected. `internal/keychainwrap` (CGo) is the shipped implementation.

**The session broker.** `internal/agent` is a Unix-socket server holding the decrypted master key for a sliding idle TTL, so concurrent jit processes share one Touch ID instead of each prompting. It verifies peer credentials as same-user before serving anything, and drops the session on screen lock or sleep (`internal/screenlock`).

Caller identity — peercred, then pid command line and parent chain — **explains and audits, it never decides.** It names the caller in the Touch ID prompt and in `jit audit`. The human approving the prompt is the decision point. Do not turn a process name into a security gate.

**Injection tiers** (the heart of the product):

| Tier | Mechanism | Code |
|---|---|---|
| 1 | Env vars into one process, then `syscall.Exec` — jit's own image is replaced | `internal/inject`, `cli/run.go` |
| 2 | Native credential-helper protocols, no intermediate file | `cli/awscred.go`, `k8scred.go`, `dockercred.go`, `gitcred.go` |
| 3–4 | Re-opened named-pipe live mounts; decoy by default, real values only to a grant's process tree | `internal/mount` |

`internal/wrap` layers over Tier 1: a directory of symlinks to the jit binary on `PATH` (`~/.jit/shims`), each re-execing as `jit run --profile wrap-<tool> -- <tool> <args>`. Three kinds in `catalog.go`: `KindShim`, `KindNative`, `KindCapture` (the last intercepts SSO CLIs at the mint, capturing minted credentials from the tool's machine-readable output).

**Scan and fix are separate commands, on purpose.** `internal/audit` (`jit scan`) is read-only in *every* mode — no flag makes it write. `internal/migrate` (`jit migrate`) is the guided fix path and reuses audit's results. Keep that boundary; it's a stated guarantee, not an accident of layering.

### The CGo seam

Three darwin-only packages are the entire non-pure-Go surface, and the first place a security reviewer looks: `internal/keychainwrap`, `internal/lineage` (libproc, FIFO reader identification — audit logging only, never a gate, because a fast-closing reader can evade it), and `internal/secureenclave`.

`internal/secureenclave` is **deferred, not merely unsigned**: Secure Enclave keychain persistence fails `-34018` because it needs a provisioning-profile-authorized entitlement that can only live in an `.app` bundle, so it cannot work in a bare-CLI shape. Re-tested 2026-07-11 with a real Apple Development identity. Don't re-litigate it as a certificate problem.

### Platform scope

**macOS-only by decision** (Apple Silicon), not by accident. A full review found no technical blocker to a Linux port — `GOOS=linux go build ./...` fails on only `internal/lineage` and `internal/keychainwrap` — but the support-matrix cost is permanent while the demand is hypothetical. Don't propose cross-platform work, and specifically do **not** do the "extract five platform interfaces" refactor: it is speculative abstraction with one implementation per seam, which `TECH_STACK.md` §3 warns against. The existing discipline (isolated CGo packages, `vault.KeyWrapper`, portable `internal/mount` and `internal/audit`) already is the portability investment.

## Conventions

**Dependency minimalism is a threat-model consistency check, not taste.** jit exists partly to mitigate malicious dependency lifecycle scripts, so a bloated supply chain undermines the product. Prefer stdlib; `golang.org/x/*` is the default extension point; every crypto or OS-security-boundary dependency gets named and justified in `TECH_STACK.md` §2. Two credential-helper JSON shapes are hand-rolled (`k8scred.go`, `awscred.go`) specifically to avoid pulling `client-go`'s tree for a five-field struct. Adding a dependency means updating `TECH_STACK.md`.

**Every `.go` file carries the SPDX header** (334/334 currently):

```go
// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
```

**DCO sign-off is a contributor rule, not the maintainer's practice.** `CONTRIBUTING.md` requires a `Signed-off-by:` line (`git commit -s`), and signing off is also how the CLA is accepted — but nothing in CI enforces it, and commits on `main` do not carry the trailer. Match the surrounding history: don't add sign-off to commits here unless asked, and do expect it on an outside contributor's PR.

**`spike/` holds throwaway experiments as separate Go modules**, deliberately exempt from `gofmt`/vet/test. Several `FINDINGS.md` files there are load-bearing history: the named-pipe re-open loop, peercred, and the Secure Enclave entitlement wall are all documented there and cited from production `doc.go` files. Read the findings before redoing a spike.

**Terminal output has a house style**, in `design/output-style.md`: bracketed `[Name] count` headers, a leading glyph carrying state (`●` green / `○` amber / `✗` red / `✓` done), hierarchy by weight with dim for everything secondary, semantic color only, whitespace columns never box-rules. Use the shared vocabulary in `internal/cli/style.go` (`cDim`, `cBold`, `cPath`, `cOK`, `cWarn`, `cRisk`, the `cPathBold`/`cOKBold` variants for the one primary thing on a line, `glyphOK`/`glyphWarn`/`glyphRisk`/`glyphDone`, `flowNames`) rather than hand-rolled `color.New(...)` — the point is that a palette change happens in exactly one place. Three report shapes share that vocabulary rather than one rigid layout: *report* (`jit scan`, `jit migrate`, `jit doctor`), *dashboard* (`jit status`), *tree* (`jit vault list`). Doctor is a findings list, not a dashboard — it was filed under dashboard for a long time and rendered as neither; see the Report section of `design/output-style.md`.

**Before implementing any change to terminal output** — layout, color, spacing, wrapping, glyphs, wording — write a preview script that renders **before vs. after**, and hand the user a `! zsh <path>` line to run it in their own terminal. Wait for their reaction before editing real code. The output is the product's surface and gets judged by eye, at the user's own width and color scheme; a diff of Go format strings does not show what the change looks like, and a captured pty is one width with the color stripped. Have the script honor the real `$COLUMNS` and also force narrow widths (50, 60), keeping real ANSI color.

**Git hygiene: never `git stash`, `git reset --hard`, or `git add -A` in this repo.** Multiple concurrent Claude sessions may share this working tree, and each of those commands has silently swept another session's in-progress work into an unrelated commit. Stage explicit paths and check `git diff --cached --name-only` before committing. To find whether a failure is yours, don't stash — read `git diff --stat HEAD -- <file>` and check whether the file appears in your own commits. If a file mixes your edits with another session's, put the change where it honestly belongs or wait for theirs to land, rather than reaching for hunk-level index surgery.

## Release

Releases are Developer ID signed and notarized by Apple through goreleaser (`.goreleaser.yml`), and `release.yml` gates a tag's publish on the full CI pipeline. Two things to know before touching this path:

- **Never ship unsigned.** `verifyStagedSignature` in `internal/cli/upgrade.go` fails closed with deliberately no override, so an unsigned release traps users out of `jit upgrade` permanently.
- jit ships a **bare Mach-O, which cannot be stapled**, so Gatekeeper always fetches the notarization ticket online. That has consequences for both the Homebrew cask's quarantine handling and for what a not-yet-notarized release does in the field.
