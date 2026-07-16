# Technology Stack: jit

**Companion to the project RFC — implementation-level technology choices for the Phase 1 (macOS) build.** The RFC states *what* jit does and where its guarantees end; this document states *what it's built out of* and why each piece was chosen over the obvious alternatives. (The RFC itself is maintained in a private planning repo; the `RFC.md:<line>` citations below refer to it.) Phase 2/3 platform stacks (§7) are exploratory previews, not commitments — consistent with RFC §5.5's "sequenced, not parallel" stance.

---

## 0. Guiding Principle: Dependency Minimalism as a Threat-Model Consistency Check

RFC §1 names "malicious dependency lifecycle scripts (`npm postinstall`)" as a primary attack surface jit exists to mitigate. A tool whose own supply chain is bloated or unaudited undermines the thing it's selling. That constrains every choice below:

- **Prefer the standard library.** Go's stdlib already covers AES-GCM, JSON, HTTP, TLS, and most I/O — reach for a dependency only when stdlib genuinely can't do it (CGo bridges to platform-native security APIs, algorithms stdlib doesn't ship like ChaCha20-Poly1305 or Curve25519 outside `x/crypto`).
- **No build-time code execution.** Go modules don't have npm-style `postinstall` hooks by default — keep it that way; reject any dependency that shells out during `go generate`/build without an explicit, reviewed reason.
- **Every crypto or OS-security-boundary dependency gets named and justified**, not pulled in transitively and forgotten. If we can't explain why we trust it, we don't ship it.
- **Pin and verify.** `go.sum` checksums, `govulncheck` in CI, and a minimal transitive dependency count (checked with `go mod graph`) are part of the stack, not an afterthought — see §6.
- **`golang.org/x/*` counts as "near-stdlib"** (maintained by the Go team, same release discipline) and is treated as the default extension point before reaching for a third-party module.

---

## 1. Language & Toolchain

**Go (current stable toolchain, 1.23+).**

| Reason | Detail |
|---|---|
| Single static binary | Matches the RFC §0 design influence (bumblebee) directly — no runtime, no interpreter, no DLL-hell on the machine it's protecting. |
| `syscall.Exec` / `execve` | Pillar III Tier 1 names this exact stdlib call (RFC.md:138) — this is Go's `syscall` package by name, not incidental. |
| Precedent | `aws-vault` (Tier 1's direct model) and `bumblebee` (§0's design influence) are both Go. Reusing the ecosystem's idioms for CLI/CGo/cross-compilation is a real advantage, not just consistency for its own sake. |
| Cross-compilation story | `GOOS=windows GOARCH=amd64 go build` gets most of the way to Phase 2's Windows target without a second toolchain — the parts that *don't* cross-compile cleanly (Secure Enclave → CNG, `execve` → `CreateProcess`) are exactly the parts the RFC already flags as needing a platform-specific redesign, not a port. |
| CGo, used narrowly | Needed only at the macOS Security.framework / LocalAuthentication.framework boundary (§2.3) and nowhere else — keeps the CGo (and therefore non-memory-safe, non-cross-compiling) surface small and auditable. |

---

## 2. Dependency Map by Concern

### 2.1 CLI structure

| Package | Role |
|---|---|
| `github.com/spf13/cobra` | Subcommand routing (`jit audit/migrate/run/export/doctor/status`, plus vault CRUD grouped under `jit vault {init,set,get,list,rm,share,revoke}`), flag parsing, `--help` generation. Industry-standard for exactly this shape of CLI (`kubectl`, `gh`, `docker`, `hugo`). |
| `golang.org/x/term` | Hidden-input password prompt (`jit vault set stripe/dev-key` with no value arg reads from a non-echoing terminal read, not shell history) and TTY detection (to decide human-readable vs. machine output when `--format` isn't passed). |

**Explicitly not** `github.com/spf13/viper` for config — see §4 (R2).

### 2.2 Cryptography — envelope encryption (Pillar II)

| Package | Role |
|---|---|
| `crypto/aes`, `crypto/cipher` (stdlib) | `AES-256-GCM` for DEK-wraps-payload and MEK-wraps-DEK, when running on hardware with AES-NI (all Apple Silicon and modern Intel Macs — ARMv8 Crypto Extensions give AES-GCM a real hardware advantage here). |
| `golang.org/x/crypto/chacha20poly1305` | `ChaCha20-Poly1305` as the configurable alternative the RFC names alongside AES-GCM (RFC.md:109) — same AEAD contract, useful if jit ever needs to run on hardware without AES acceleration, or to hedge against a future AES-specific finding. **Not yet adopted:** the shipped envelope (v2) is AES-256-GCM only. The envelope's `version` field — written from day one, and checked on read since v2 — is the designed selection point when this lands: a per-file choice, not a global one, and an old jit refuses a newer version with "upgrade jit" instead of misreading it. |
| `golang.org/x/crypto/hkdf` | Derives the symmetric key-wrapping key from the ECDH shared secret produced by the Secure Enclave (see §3) — never uses the raw ECDH output directly as a key. |
| `crypto/rand` (stdlib) | DEK generation, nonces. Never `math/rand` for anything touching a secret. |
| `golang.org/x/crypto/argon2` | Derives the export key for `jit vault export`/`import`'s local encrypted backup (GAPS.md #23) from a caller-supplied passphrase — memory-hard specifically to resist offline brute-force against a stolen export file, the actual threat model for a file that (unlike the vault's own per-secret `.enc` files) is deliberately portable off-device. Not the same key-derivation role as `hkdf` above: HKDF stretches an *already high-entropy* ECDH secret, Argon2id derives from a *human-memorable, low-entropy* passphrase — the two aren't interchangeable. |

### 2.3 macOS Secure Enclave / Keychain / local auth (Pillar II)

| Package | Role |
|---|---|
| `github.com/keybase/go-keychain` | Keychain Services wrapper for storing/retrieving the wrapped-DEK metadata and driving `SecAccessControl`. Evaluate its Secure Enclave key-generation coverage (`kSecAttrTokenIDSecureEnclave`) against what Pillar II needs before committing — see fallback below. **Not adopted** — the spike below tested the hand-written CGo path directly and it worked, so `internal/keychainwrap` uses that as the real default, not this package; see §8's "never adopted" table. |
| Hand-written CGo against `Security.framework` (fallback/supplement) | If `go-keychain` doesn't fully expose `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` + `kSecAccessControlBiometricsAny` (RFC.md:110), or `SecKeyCopyKeyExchangeResult` for ECDH, a narrow purpose-built CGo shim covers exactly those three calls. Keep this file small and isolated — it's the one place in the codebase that isn't pure Go, and it's the one place a reviewer should look first. |
| `LocalAuthentication.framework` (via the same CGo boundary, only if custom prompt text is needed) | The OS surfaces the Touch ID / passcode-fallback UI automatically when a `SecAccessControl`-gated key is used — for MVP, rely on that default system prompt rather than driving a custom `LAContext`, to keep the CGo surface minimal. Revisit only if product wants jit-branded prompt copy. |

This is the one layer of the stack that is unavoidably macOS-only and unavoidably CGo — everything else in Phase 1 is portable Go, which is deliberate: it minimizes what Phase 2's Windows port (§7) has to throw away.

**Spike confirmed (see `spike/secure-enclave/FINDINGS.md`):** hand-written CGo directly against `Security.framework` + `LocalAuthentication.framework` generates a Secure-Enclave-backed P-256 key, gates it with `kSecAccessControlBiometryAny`, and performs `SecKeyCopyKeyExchangeResult` (ECDH) successfully — confirmed with a real, user-approved Touch ID prompt, not just a code-path check. This validates the core Pillar II mechanism ahead of building the vault around it; whether `go-keychain` alone would have sufficed was never resolved because the hand-written path was tested directly and works, so it's the default going forward rather than a fallback.

**Finding that changes §5 below:** persisting the key to the keychain (`kSecAttrIsPermanent: YES` — required for a real MEK that survives across process invocations) failed under ad-hoc signing with `-34018 errSecMissingEntitlement`. Real code signing with a Team ID is therefore a **local development-time requirement**, not only a pre-distribution one — but re-testing on 2026-07-11 with a real Apple Development identity showed a Team ID is **necessary but not sufficient**: the persistent path additionally needs a provisioning-profile-authorized entitlement that can only live in an `.app` bundle, so it can't work in a bare-CLI shape at all. See §5 and `spike/secure-enclave/FINDINGS.md`'s 2026-07-11 update.

### 2.4 In-process secret hygiene

| Package | Role |
|---|---|
| `github.com/awnumar/memguard` | Locks (`mlock`) and explicitly zeroes the buffers holding the decrypted DEK and secret payload between decryption and hand-off (exec/pipe write). Go's GC does not guarantee zeroing or non-swapping of a `[]byte` holding a secret — B1 already concedes the target process gets the plaintext, but *jit's own* residency window before that hand-off is exactly the thing this narrows. **Not adopted for this first cut** — `internal/vault/crypto.go`'s `wipe()` (plain zero-in-place, no `mlock`) was judged sufficient for now; `spike/memguard/FINDINGS.md` already validated this package works whenever that hardening pass happens. See §8. |

### 2.5 Storage & manifest formats

| Format / Package | Role |
|---|---|
| `encoding/json` (stdlib) | `.enc` envelope files (Pillar II) and NDJSON audit records (§4 of the RFC) — no reason to pull in a third-party JSON library for either. |
| `gopkg.in/yaml.v3` | Profile manifests (`.jit/profiles/*.yaml`, Pillar IV) and the Phase 2 `.jit-policy.yaml`. YAML is the RFC's own choice for both (RFC.md:117-122, RFC.md:407-451), not something this doc is introducing. |
| Atomic file writes: `os.CreateTemp` + `os.Rename` (stdlib) | Pillar I's "atomic, file-per-secret" claim (RFC.md:80) needs an actual atomic-write pattern (write to temp file in the same directory, `fsync`, rename over the target) — worth naming explicitly since "atomic" is a promise, not just an adjective. |

### 2.6 IPC — `jit-agent` session broker (Pillar II, III)

| Package | Role |
|---|---|
| `net` (stdlib) | Unix domain socket for the TTL-scoped MEK cache (RFC.md:111). |
| `golang.org/x/sys/unix` | Socket file permissions (`0600`, owner-only), and peer-credential verification (`LOCAL_PEERCRED` on Darwin) so the agent can confirm a connecting process belongs to the same UID before releasing anything from the cache. The FIFO mount itself ended up gated a different way (decoy-by-default, `internal/mount.RevealState`) — `spike/fifo-reader-identify/FINDINGS.md` found the peer-credential approach here doesn't carry over to a named pipe the way it does for this socket. |

### 2.7 Named-pipe injection (Pillar III, Tiers 3–4)

| Package | Role |
|---|---|
| `golang.org/x/sys/unix` (`unix.Mkfifo`) | Stdlib has no `mkfifo` — this is the only way to create the re-opened FIFO at the `.env` path (Tier 3) or the allowlisted legacy-tool path (Tier 4). |
| Custom re-open loop (no library) | "Re-open the pipe on every new `open()`" (RFC.md:142) is a small hand-rolled loop around `unix.Mkfifo` + blocking open/write — there isn't an existing library for this specific "living FIFO" pattern; it's simple enough that pulling in a dependency for it would violate §0. |

### 2.8 Process lineage (Phase 2, RFC §5.1)

| Package | Role |
|---|---|
| `github.com/mitchellh/go-ps` | Cross-platform process listing with parent-PID resolution; on Darwin it's pure Go over `sysctl(KERN_PROC)` — no CGo needed for this one, unlike §2.3. Matches the three OS-native mechanisms the RFC names (`sysctl`, `/proc`, `ToolHelp32`) without hand-rolling each. |

### 2.9 Terminal UX — `jit audit` human-readable report

| Package | Role |
|---|---|
| `github.com/fatih/color` | Color-coded risk banner and per-category counts (RFC.md:179-181). Deliberately not a full TUI framework (Bubble Tea, etc.) — `jit audit`'s default output is a report, not an interactive UI, and a heavier dependency isn't earned here. |

### 2.10 Native credential-helper protocol types (Pillar III, Tier 2)

| Package | Role |
|---|---|
| No package for Kubernetes `ExecCredential` | Originally planned to reuse `k8s.io/client-go/pkg/apis/clientauthentication`'s upstream struct, but `client-go` pulls in a large transitive dependency tree (the full k8s API machinery) just for one ~5-field JSON type — the §0 dependency-minimalism principle argues against that trade. `internal/cli/k8scred.go` hand-rolls `k8sExecCredentialStatus`/`k8sExecCredentialOutput` directly against the documented `client.authentication.k8s.io/v1` shape instead, the same call already made for AWS below. |
| No package for AWS `credential_process` | AWS doesn't publish a Go struct for the `credential_process` JSON shape (`Version`, `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`) — it's four fields, defined directly in jit's code (`internal/cli/awscred.go`) against AWS's documented spec. |

### 2.11 Phase 2 — team sharing (RFC §5.2)

| Package | Role |
|---|---|
| `filippo.io/age` | The RFC names "X25519 / `age` protocol" directly (RFC.md:399) — reuse the actual `age` library for recipient-based encryption (`age.X25519Recipient`/`Identity`) rather than reimplementing its wire format. Well-audited, minimal, maintained by a working cryptographer. See §3 for why this is a *second* curve, not a replacement for Secure Enclave's P-256. |

### 2.12 Phase 2 — SIEM/webhook delivery (RFC §5.3)

| Package | Role |
|---|---|
| `net/http` (stdlib) | Base client for Datadog/Splunk/Slack/Teams webhook delivery. |
| `github.com/hashicorp/go-retryablehttp` | Backoff/retry wrapper so a transient network blip doesn't silently drop a high-severity event (failed auth, blocked lineage, tripped velocity limit, canary use) — these are exactly the events where "we tried once and gave up" is the wrong failure mode. |

---

## 3. Architecture Note: Two Curves, Two Purposes

Worth stating explicitly because it's easy to conflate: **Phase 1's local MEK and Phase 2's team-sharing keys use different elliptic curves, for a hardware reason, not a style choice.**

- **Apple's Secure Enclave only supports NIST P-256** (`kSecAttrKeyTypeECSECPrimeRandom`) for enclave-resident key generation and ECDH — it does not support Curve25519. Pillar II's device-local MEK is therefore necessarily P-256, wrapped via `SecKeyCopyKeyExchangeResult` (ECDH) → HKDF → AEAD key (§2.3, §2.2).
- **`age`'s recipient protocol (Phase 2 team-sharing) is X25519** (RFC.md:399) — a software-only curve chosen for the `age` ecosystem's own reasons, unrelated to what any given recipient's device hardware supports.

These two layers don't need to interoperate at the curve level — the Secure Enclave P-256 key protects a *local* device's DEK access, while X25519/`age` protects a DEK being *shared* to another identity. Keep this boundary explicit in the code (two distinct key types, not a generic "asymmetric key" abstraction) so a future refactor doesn't accidentally try to hand a P-256 Secure Enclave key to the `age` recipient path or vice versa.

---

## 4. Rejected Alternatives

Mirroring the RFC's own boundary-table style (§2) — stating what was *not* chosen and why, so the reasoning doesn't get re-litigated later.

| # | Rejected | In favor of | Why |
|---|---|---|---|
| **R1** | A full TUI framework (Bubble Tea / `tview`) for `jit audit` | `fatih/color` + plain formatting | The audit report (RFC.md:178-195) is a report, not an interactive surface — no scrolling panes, no keybindings. A TUI framework is real weight for zero functional gain here. |
| **R2** | `spf13/viper` for config | `gopkg.in/yaml.v3` + explicit flag parsing | Viper pulls a large transitive tree (remote config providers, multiple format decoders jit doesn't use) for a feature set (profiles, policy file) that's two flat YAML shapes. Directly in tension with §0's dependency-minimalism principle for a security tool. |
| **R3** | A generic secrets-manager SDK (e.g., wrapping HashiCorp Vault's client) | Purpose-built envelope format (Pillar II) | jit's threat model (local-first, hardware-enclave-bound, no server) doesn't match Vault's (networked, server-mediated) — adopting its SDK would import an entire client for a protocol jit doesn't speak. |
| **R4** | `memfd_create`-backed shared memory for Tier 4 (legacy tools needing real random access) | Explicitly unsupported in Phase 1, allowlist stays narrow | `memfd_create` is Linux-only (B4, RFC.md:59) — building a Phase 1 mechanism around it would mean either a macOS-only fake or dead code until the Linux port. Matches the RFC's own explicit non-goal here. |
| **R5** | A monolithic vault database (BoltDB/SQLite) for local storage | File-per-secret tree (Pillar I) | The RFC is explicit that a single DB file reintroduces the split-brain-under-sync problem (RFC.md:93) that file-per-secret avoids. A database library would be solving a problem the architecture deliberately doesn't have. |
| **R6** | Hand-rolling the `age` wire format instead of importing the library | `filippo.io/age` | Reimplementing a recipient-stanza AEAD format is exactly the kind of "rolled our own crypto encoding" a security review flags first, for a protocol the RFC already named as the reference (RFC.md:399). |

---

## 5. Build, Signing, Distribution

| Concern | Tooling |
|---|---|
| Cross-compilation & release packaging | `goreleaser` — single config drives `darwin/arm64` + `darwin/amd64` builds today, and the same pipeline extends to `windows/amd64` when Phase 2 ships. |
| Code signing | Apple Developer ID Application certificate + `codesign`. **Required for two separate reasons**, not one: (1) Gatekeeper will block an unsigned/unnotarized binary from running at all on a clean macOS install — the distribution reason this was originally scoped for; (2) confirmed by the Secure Enclave spike (`spike/secure-enclave/FINDINGS.md`) — persisting a Secure-Enclave-backed key to the keychain fails with `errSecMissingEntitlement` under ad-hoc signing, so a real Team ID is a prerequisite — **but not sufficient on its own.** A free Apple ID "Personal Team" cert (obtained and tested 2026-07-11) clears the ad-hoc gate yet the persistent-key path *still* fails `-34018`: it additionally needs the `application-identifier`/`keychain-access-groups` entitlement authorized by a **provisioning profile**, which per Apple's official ["Signing a daemon with a restricted entitlement"](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement) can only be embedded in an `.app` bundle (`<Bundle>.app/Contents/embedded.provisionprofile`), never a bare CLI binary. **So SE persistence cannot work through `go install` / Homebrew-formula distribution at all** — see `spike/secure-enclave/FINDINGS.md`'s 2026-07-11 update for the full test log. Actual SE use would require the paid Developer ID Application certificate + notarization + an `.app`-wrapped bundle (the jit-agent is the natural component to bundle); until then `internal/keychainwrap` (app-level `LAContext`) is the shipped interim. |
| Notarization | `xcrun notarytool` as part of the release pipeline — stapled to the release artifact before distribution. |
| Distribution channel | Homebrew tap (`brew install jit`) — matches how developers already install `aws-vault`, `bumblebee`-style tools, and most of the CLI ecosystem this competes with. `goreleaser` generates the tap formula directly from the same release config. |

---

## 6. Testing & Supply-Chain Hygiene

Given §0's framing — a security tool's own build practices are part of its credibility — these aren't optional nice-to-haves:

| Tool | Purpose |
|---|---|
| `go test` + `github.com/stretchr/testify` | Standard unit/table-driven tests; `testify/assert`/`require` for readable failure output. |
| Go native fuzzing (`go test -fuzz`) | Targeted at the `jit audit` scanners (shell-config parsing, `.env` parsing, MCP JSON parsing) — these parse untrusted, attacker-shaped input (a malicious `.mcp.json` or crafted shell config) by definition. |
| `govulncheck` | Official Go team tool — CI gate against known CVEs in the dependency graph, run on every PR. |
| `staticcheck` | General Go static analysis in CI. |
| `gosec` | Security-specific static analysis (hardcoded credentials, weak crypto primitives, command injection) — points at the codebase, not just dependencies. |
| `go mod verify` / committed `go.sum` | Checksum verification on every build; no `GOFLAGS=-mod=mod` auto-upgrades in CI. |
| SBOM generation (`syft` or `cyclonedx-gomod`) at release time | A security product should be able to hand a customer a software bill of materials for its own binary — publish one per release rather than making it a support request. |

---

## 7. Future Platform Stacks (Exploratory — not committed)

Per RFC §5.5, these ship sequentially and each gets its own design pass; listed here only so the eventual work isn't starting from zero.

**Windows (next):**

| Concern | Likely package/API |
|---|---|
| Process replacement | No `execve` equivalent — needs a `CreateProcess`-based redesign of Pillar III Tier 1 (RFC.md:461), via `golang.org/x/sys/windows` or CGo against `kernel32.dll`. |
| Hardware-bound MEK | TPM 2.0 / CNG-DPAPI-NG — `github.com/google/go-tpm` for TPM 2.0 primitives, CGo against `ncrypt.dll`/`bcrypt.dll` for CNG key storage. |
| Local auth | Windows Hello via the `Windows.Security.Credentials.UI` WinRT API — likely needs a WinRT interop layer (e.g. `github.com/go-ole/go-ole` or hand-written syscall bindings); no mature pure-Go wrapper exists today, so this is genuinely open. |

**Linux (after Windows):**

| Concern | Likely package/API |
|---|---|
| Keyring integration | `github.com/godbus/dbus/v5` against the `org.freedesktop.secrets` D-Bus API (gnome-keyring, kwallet). |
| TPM-backed Secret Service (minority of dev laptops, per B2) | `github.com/google/go-tpm`, with `jit status` surfacing `hardware-bound` vs. `os-keyring-bound` per RFC.md:462. |
| Random-access injection upgrade (Tier 4) | `memfd_create` becomes available here — revisit R4 once this port exists. |

---

## 8. Summary — Actual `go.mod` (Phase 1, macOS only)

This used to be an "illustrative" preview written before the build existed; now that Phase 1's core is shipped, it's the real dependency list plus what each real package under `internal/` actually uses it for — with the handful of originally-planned packages that were deliberately never adopted called out explicitly, not silently dropped.

```
require github.com/spf13/cobra v1.10.2   // CLI framework

require (
    github.com/fatih/color v1.19.0      // audit report formatting (internal/audit/report.go)
    golang.org/x/crypto v0.53.0         // ssh: parsing SSH private keys (internal/audit/privatekey.go);
                                         // argon2: passphrase key derivation for jit vault export/import
                                         // (internal/vault/export.go, GAPS.md #23) — NOT per-secret vault
                                         // crypto, which is stdlib crypto/aes+crypto/cipher (AES-256-GCM)
                                         // directly either way; see internal/vault/crypto.go
    golang.org/x/sys v0.46.0            // unix.Mkfifo (internal/mount), socket peer creds (internal/agent)
    golang.org/x/term v0.44.0           // hidden password prompt (jit vault set)
    gopkg.in/yaml.v3 v3.0.1             // profile manifests, mount registry, kubeconfig parsing
)
```

Vault/keychain access to `LocalAuthentication`/`Security.framework` is a direct CGo/Objective-C bridge (`internal/keychainwrap/*.m`/`*.h`) rather than a Go wrapper package — see §2.3.

**Planned here but never adopted, deliberately — not an oversight:**

| Package | Originally planned for | Why it didn't happen |
|---|---|---|
| `github.com/keybase/go-keychain` | Keychain / Secure Enclave access | `internal/keychainwrap` bridges `Security.framework`/`LocalAuthentication` directly via CGo instead — see §2.3's own reasoning. |
| `github.com/awnumar/memguard` | Locked, zeroed secret buffers | `spike/memguard/FINDINGS.md` validated it works, but `internal/vault/crypto.go`'s `wipe()` (a plain zero-in-place loop) was judged enough for this first cut — its own doc comment names `memguard` as the real hardening to grow into, not yet done. |
| `k8s.io/client-go/pkg/apis/clientauthentication` | `ExecCredential` type (Tier 2) | Pulls in the full k8s API machinery's transitive dependency tree for one ~5-field JSON type — see §2.10, which now hand-rolls it instead, the same call already made for AWS's `credential_process` shape. |
| `github.com/mitchellh/go-ps` | Process lineage (Phase 2, §2.8) | Phase 2 isn't built yet at all — correctly out of a Phase 1 `go.mod`, kept here only as a forward pointer to §2.8. |

Phase 2 additions (`filippo.io/age`, `github.com/hashicorp/go-retryablehttp`) are likewise deliberately excluded from the Phase 1 build to keep the shipped binary's dependency graph matched to what Phase 1 actually uses.
