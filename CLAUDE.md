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
goreleaser check                                                              # needs goreleaser >= v2.13: the cask's `binaries:` field
goreleaser release --snapshot --clean --skip=publish,sign,notarize,homebrew   # homebrew skipped: a snapshot must never touch the tap
```

`release.yml` pins the goreleaser MAJOR (`~> v2`), so CI always has a new
enough one; a local `goreleaser check` on v2.12.5 or older rejects the cask
block with "field binaries not found in type config.HomebrewCask" — that is
the tool being old, not the config being wrong.

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

`internal/wrap` layers over Tier 1: a directory of symlinks to the jit binary on `PATH` (`~/.jit/shims`), each re-execing as `jit run --profile wrap-<tool> -- <tool> <args>`. Four kinds in `catalog.go`: `KindShim`, `KindNative`, `KindCapture` (intercepts SSO CLIs at the mint, capturing minted credentials from the tool's machine-readable output) and `KindRunGrant`.

**Scan and fix are separate commands, on purpose.** `internal/audit` (`jit scan`) is read-only in *every* mode — no flag makes it write. `internal/migrate` (`jit migrate`) is the guided fix path and reuses audit's results. Keep that boundary; it's a stated guarantee, not an accident of layering.

**Prevention is a third mode, not an injection tier.** `internal/guard` (`jit guard`) installs shell hooks that stop a credential being *recorded* in the first place — today one: a zsh `zshaddhistory` hook that keeps credential-carrying commands out of `$HISTFILE` while leaving them usable in the session. It delivers no secret, so it appears in no tier above. Two rules govern it: it must **fail open** (a hook that eats history or hangs the prompt is worse than one that misses a token), and its cheap in-shell admit test must never reject a line the real check would match — the same obligation `historyLineMayHoldToken` carries in `internal/audit` — the zsh condition is RENDERED from `audit.HistoryAdmitRule()` (literals, run length, run class) rather than retyped beside it, so the two cannot drift, and `internal/guard` imports `internal/audit` for it — and enforced by tests that drive the shipped hook through a real `zsh` over the corpus both admit tests share.

### The CGo seam

**Four** darwin-only packages `import "C"` and are the entire non-pure-Go surface, the first place a security reviewer looks: `internal/keychainwrap`, `internal/lineage` (libproc, FIFO reader identification — audit logging only, never a gate, because a fast-closing reader can evade it), `internal/pasteboard` (plaintext secrets onto NSPasteboard) and `internal/screenlock` (the lock/sleep trigger that drops the session). `internal/secureenclave` is **not** one of them — it contains only a `doc.go` and no C at all; it was long counted here, which left `pasteboard` and `screenlock` outside the surface reviewers were told to focus on.

`internal/secureenclave` is **deferred, not merely unsigned**: Secure Enclave keychain persistence fails `-34018` because it needs a provisioning-profile-authorized entitlement that can only live in an `.app` bundle, so it cannot work in a bare-CLI shape. Re-tested 2026-07-11 with a real Apple Development identity. Don't re-litigate it as a certificate problem.

### Platform scope

**macOS-only by decision** (Apple Silicon), not by accident. A full review found no technical blocker to a Linux port — `GOOS=linux go build ./...` fails on only `internal/lineage` and `internal/keychainwrap` — but the support-matrix cost is permanent while the demand is hypothetical. Don't propose cross-platform work, and specifically do **not** do the "extract five platform interfaces" refactor: it is speculative abstraction with one implementation per seam, which `TECH_STACK.md` §3 warns against. The existing discipline (isolated CGo packages, `vault.KeyWrapper`, portable `internal/mount` and `internal/audit`) already is the portability investment.

## Conventions

**Dependency minimalism is a threat-model consistency check, not taste.** jit exists partly to mitigate malicious dependency lifecycle scripts, so a bloated supply chain undermines the product. Prefer stdlib; `golang.org/x/*` is the default extension point; every crypto or OS-security-boundary dependency gets named and justified in `TECH_STACK.md` §2. Two credential-helper JSON shapes are hand-rolled (`k8scred.go`, `awscred.go`) specifically to avoid pulling `client-go`'s tree for a five-field struct. Adding a dependency means updating `TECH_STACK.md`.

**Every `.go` file carries the SPDX header** (390/390 currently):

```go
// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
```

**DCO sign-off is a contributor rule, not the maintainer's practice.** `CONTRIBUTING.md` requires a `Signed-off-by:` line (`git commit -s`), and signing off is also how the CLA is accepted — but nothing in CI enforces it, and commits on `main` do not carry the trailer. Match the surrounding history: don't add sign-off to commits here unless asked, and do expect it on an outside contributor's PR.

**`spike/` holds throwaway experiments as separate Go modules**, deliberately exempt from `gofmt`/vet/test. Several `FINDINGS.md` files there are load-bearing history: the named-pipe re-open loop, peercred, and the Secure Enclave entitlement wall are all documented there and cited from production `doc.go` files. Read the findings before redoing a spike.

**Terminal output has a house style**, in `design/output-style.md`: bracketed `[Name] count` headers, a leading glyph carrying state (`●` green / `○` amber / `✗` red / `✓` done), hierarchy from bold alone with everything secondary left plain, semantic color only, whitespace columns never box-rules. The palette is six inks and one attribute — green, amber, red, cyan, bold, plain — and there is **no dim/faint**: it was removed on 2026-08-06 because half-opacity text is what most of a scan report was made of, and `TestNoFaintText` now fails the build if it comes back. Every ink and every glyph is defined in **`internal/style`** — below `cli`, `audit` and `ui` so all three share it (`internal/cli` imports `internal/audit`, so the vocabulary could never live in `cli`). `internal/cli/style.go` re-exports it under short local names (`cBold`, `cPath`, `cOK`, `cWarn`, `cRisk`, `cPathBold`, `cOKBold`, `cWarnBold`, `glyphOK`/`glyphWarn`/`glyphRisk`/`glyphDone`/`glyphAction`/`glyphMark`/`glyphBullet`/`glyphBranch`/`glyphRule`/`glyphLock`, plus `flowNames`). Never hand-roll `color.New(...)` — `TestPaletteIsCentralised` fails on it. Typing a glyph literal at a call site is the same mistake and is caught the same way, by `TestNoGlyphLiterals` — it tokenizes with `go/scanner`, so glyphs in comments stay free, and exempts `_test.go`, `style.go` and `markdown.go` (a markdown document, not terminal output). All four style guards walk the whole tree, so rule 5's "on every surface" holds in `audit`, `migrate`, `ui` and `wrap`, including the scan report. Glyph rules: `●○✗✓` are row states, `!` is a findings item the user must fix, `→` is the one command to type (cyan, line-leading) or "maps to" (plain, inline), `•` a stateless bullet, `└` evidence, `─` only a table subtotal, `🔐` only the Touch ID wait. **Keep output text short** — one clause per line, ~72 chars natural length, truncate variable content rather than wrapping it, state a shared fact once on the group header. The point of the seam is that a palette change happens in exactly one place. Three report shapes share that vocabulary rather than one rigid layout: *report* (`jit scan`, `jit migrate`, `jit doctor`), *dashboard* (`jit status`), *tree* (`jit vault list`). Doctor is a findings list, not a dashboard — it was filed under dashboard for a long time and rendered as neither; see the Report section of `design/output-style.md`.

**Before implementing any change to terminal output** — layout, color, spacing, wrapping, glyphs, wording — write a preview script that renders **the proposed output only**, and hand the user a `! zsh <path>` line to run it in their own terminal. Wait for their reaction before editing real code. Do **not** render before-and-after pairs: the current output is already in the user's scrollback, and doubling every block halves how much of the real thing fits on screen and makes it harder to judge. The output is the product's surface and gets judged by eye, at the user's own width and color scheme; a diff of Go format strings does not show what the change looks like, and a captured pty is one width with the color stripped. Have the script honor the real `$COLUMNS` and also force narrow widths (50, 60), keeping real ANSI color.

**Git hygiene: never `git stash`, `git reset --hard`, or `git add -A` in this repo.** Multiple concurrent Claude sessions may share this working tree, and each of those commands has silently swept another session's in-progress work into an unrelated commit. Stage explicit paths and check `git diff --cached --name-only` before committing. To find whether a failure is yours, don't stash — read `git diff --stat HEAD -- <file>` and check whether the file appears in your own commits. If a file mixes your edits with another session's, put the change where it honestly belongs or wait for theirs to land, rather than reaching for hunk-level index surgery.

## Release

Releases are Developer ID signed **and notarized** through goreleaser (`.goreleaser.yml`), with `wait: true` so the verdict is in before publishing. Notarization was switched off for a stretch — this account's notary hung 8 of 9 submissions "In Progress" for hours and held releases hostage for days — and came back in v0.80.0 once `spike/notarize-e2e/FINDINGS.md`'s numeric gate was met (three consecutive Accepted across two days). Don't re-litigate it as broken; do read that FINDINGS before changing the notarize block. `release.yml` gates a tag's publish on the full CI pipeline, called as a reusable workflow with `needs:`, so the gate is real rather than advisory.

Distribution is Homebrew (`brew install jitpass/tap/jitpass`, cask in `jitpass/homebrew-tap`) plus the signed release tarball (curl) + `jit upgrade` — `upgrade.go` tells a Caskroom-resolved copy to reinstall from the tarball rather than deferring to `brew upgrade`. Four things to know before touching this path:

- **Never ship unsigned**, and know where that is enforced. `verifyStagedSignature` in `internal/cli/upgrade.go` fails closed with deliberately no override; `release.yml`'s "Require Developer ID signing secrets" preflight is what stops an unsigned artifact being published in the first place. Without it, goreleaser's `isEnvSet` gate treats an empty secret as unset and the notary pipe answers with `Skip`, not an error — so a missing secret publishes unsigned, silently. An unsigned release is recoverable (a signed one replaces it, since `jit upgrade` targets `/releases/latest`).
- **The Team ID is the unrecoverable one, and it is now a LIST.** `upgradeTeamIDs` (`upgrade.go`) holds every accepted Apple Team ID, most current first; `verifyStagedSignature` tries each. The trap it defuses: the rejecting code lives in the ALREADY-INSTALLED binary, so a certificate re-issued under a new Team ID would have every copy in the field reject every future release forever, with no release able to fix it. The migration is therefore: add the successor here, ship, let it propagate, and only THEN switch certificates — removing the old ID is a separate, much later change. `upgradeTeamIDs[0]` is what `jit doctor` reports and what the release workflow asserts on, so a release accidentally signed with an outgoing identity fails the gate rather than passing as "signed, close enough". `signatureRequirement` also carries Apple's Developer-ID marker OIDs, so an Apple *Development* cert from the same team no longer satisfies it.
- jit ships a **bare Mach-O, which cannot be stapled** (`xcrun stapler` needs a bundle/dmg/pkg), so Gatekeeper fetches the notarization ticket ONLINE on first run. That is what makes the cask viable without an `xattr -dr com.apple.quarantine` hook: Homebrew quarantines its downloads, and the online ticket clears them. Do not add that hook back — it discards the check notarization pays for, and Apple has signalled it may close the bypass. The curl path sets no quarantine bit at all, so it never consults the ticket.
- **Verify what was PUBLISHED, not what was built.** `release.yml` publishes a draft, downloads the release's own assets, checks the tarball against the published `checksums.txt` and the binary against `jit upgrade`'s own requirement, and only then undrafts. The checksum half exists because of a real v0.80.0 incident: a re-run rebuilt the tarball and pushed a cask carrying the rebuild's hash while GitHub kept the first run's assets (`replace_existing_artifacts` did not replace them), so `brew install` died on a mismatch that a `dist/`-based check could never see. `jit upgrade` fetches the archive and `checksums.txt` independently, so a release whose manifest disagrees with its own tarball breaks every self-update.
