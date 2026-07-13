# RFC / Design Specification: jit

**Local-First Developer Endpoint Protection & Zero-Plaintext Secret Runtime**

---

## 0. Design Influence

`jit`'s scope discipline is modeled on [`bumblebee`](https://github.com/perplexityai/bumblebee) (Perplexity's read-only developer-endpoint inventory scanner): a single static binary, an explicit table of what is and is not read/executed, and — critically — a written boundary for every capability that touches something sensitive (bumblebee parses MCP configs for server inventory but states plainly that it "does not emit those values" for any credentials found in `env` blocks).

The two tools are complementary rather than overlapping:

- **bumblebee** answers "what's on disk right now, and does it match a known-bad package/version?" — passive, read-only, point-in-time.
- **jit** answers "how do we stop plaintext secrets from being on disk at all?" — active, mutating, continuous.

A fleet running both gets detection (bumblebee flags a compromised package or an `.env` file matching an exposure catalog) and prevention (jit means there's no plaintext `.env` file to expose in the first place). Section 2 below borrows bumblebee's format directly: every mitigation claim is paired with a stated boundary.

A second influence, pulled in after reviewing [1Password's CLI docs](https://www.1password.dev/cli): its `.env`-mounting model — a live named pipe served at the conventional `.env` path rather than a rewritten file full of pointer strings — is a better Phase 1 default than static pointer-rewriting, because pointer-rewriting silently breaks any app that reads `.env` directly instead of being launched through `jit run`. Adopting it isn't free, though: it reopens exactly the AI-agent/MCP threat (attack surface row 2) that pointer-rewriting was built to close, unless paired with per-reader authorization. See the reworked Pillar III and new boundary **B10** below.

A third influence: an existing Jamf-deployed "Developer Secrets Scanner" Extension Attribute and its fleet-reporting script, already running in production. Its category breakdown (shell configs, `.env` files, credential files, MCP-embedded secrets, IaC variable files, suspicious filenames, private keys) and risk-scoring model (production-indicator and public-IP matches escalate to Critical regardless of count; otherwise scored by finding volume and category severity) map directly onto `jit audit`'s read-only scan (§4) and are adopted as-is rather than reinvented.

---

## 1. Executive Summary

Modern developer endpoints represent a high-value, poorly defended attack surface. Infostealers (e.g., Lumma, RedLine), malicious dependency lifecycle scripts (`npm postinstall`), and over-privileged AI assistants with local filesystem access (e.g., Model Context Protocol servers) routinely target developer machines to harvest cloud credentials and API keys.

**jit** is a local-first secret runtime CLI built in Go. It reduces the plaintext-at-rest footprint of developer-workstation secrets without introducing the latency, offline fragility, or vendor lock-in of a hosted SaaS vault.

It does this by storing secrets locally by default (with standard cloud storage — Google Drive, OneDrive — available as an opt-in for encrypted multi-device sync), anchoring encryption keys in the OS hardware enclave with native local authentication, and injecting secrets into application memory either at process-launch time via process replacement, or via a live-mounted virtual `.env` file for apps that read `.env` directly regardless of how they were launched (§3, Pillar III).

This is a mitigation, not a guarantee: Section 2 states plainly what `jit` does not and cannot protect against, most importantly that a secret is still fully plaintext inside the target process once injected. The value proposition is eliminating *idle* plaintext exposure (files on disk, shell history, synced configs) — not eliminating exposure to the process the secret is deliberately handed to.

**Platform scope:** Phase 1 targets **macOS only** (Apple Secure Enclave, Touch ID / device passcode). Windows (TPM 2.0, CNG/DPAPI-NG, Windows Hello) is the intended next platform once macOS is validated in real usage. Linux (Secret Service / keyring backends) comes after Windows and, per B2, ships best-effort/software-keyring-bound rather than hardware-bound on most developer laptops. Nothing below should be read as a cross-platform Phase 1 commitment.

### Protected Attack Surfaces

| # | Attack Surface | Primary Vulnerability | Phase 1 Mitigation |
|---|---|---|---|
| 1 | Application `.env` files | Plaintext secrets committed to git, scraped by malware, or read by local AI agents. | Live-mounted virtual `.env` (Pillar III, Tier 3) — real values never sit on disk; decoy-by-default, real values only during a short revealed window (B10). |
| 2 | AI tool & MCP configs | Plaintext API tokens embedded in `claude_desktop_config.json`, `mcp.json`, editor settings. | Launch via `jit run` (Tier 1) — the MCP host config invokes the wrapper instead of embedding a token; the static JSON file never holds a real value. |
| 3 | Shell init scripts | `export AWS_SECRET="..."` in `.zshrc`/`.bashrc` polluting the global OS environment. | Replaced with session-scoped `eval "$(jit export --profile ...)"` (Pillar IV) — nothing persists in shell init files. |
| 4 | Cloud credential files | Static files (`~/.aws/credentials`, `~/.kube/config`, `.npmrc`) targeted by automated scrapers. | Native credential helper where the tool supports one (Tier 2); narrow validated pipe allowlist otherwise (Tier 4). |
| 5 | Private keys | Unencrypted or weakly protected SSH/PGP keys (`~/.ssh/id_ed25519`) on disk. | Detection only in Phase 1 — `jit audit` flags missing passphrases and loose permissions (see below); active delegation to hardware-bound agents is Phase 2. |

`jit audit`'s read-only scan (§4) covers these five plus two detection-only extensions with no active Phase 1 mitigation yet — IaC variable files (`terraform.tfvars` and similar) and suspicious filenames — because visibility is cheaper to ship safely than an automated fix for either.

---

## 2. Threat Model Boundaries & Known Limitations

State this section before the architecture. Every mitigation in Section 3 has a stated edge; a reader should be able to tell exactly where protection stops without reading the implementation.

| # | Boundary | What happens instead | Why it's a boundary, not a bug |
|---|---|---|---|
| **B1** | Secrets are plaintext inside the target process once injected. | A compromised or malicious dependency running *inside* `npm run dev` (the process jit just execed into) reads `process.env` normally and gets the real secret. | Any secret-injection tool has this property — the application needs the real value to function. `jit` narrows the *window and surface* of exposure (no idle file on disk, TTL-bound) but does not and cannot sandbox the consumer of the secret. Do not market this as "zero-leakage" for a compromised target process. |
| **B2** | Hardware-enclave parity will be uneven once other platforms ship. | Phase 1 is macOS-only (Secure Enclave — a real hardware-bound guarantee). When Windows ships (Phase 2 platform target), TPM 2.0/CNG gives a comparable guarantee. Linux (Phase 3, after Windows) mostly lacks a TPM-backed Secret Service on dev laptops — `pam_fprintd`/gnome-keyring/kwallet are typically software-only keyrings. | Each platform's guarantee level (`hardware-bound` vs. `os-keyring-bound`) must be documented explicitly when that platform ships, rather than implying uniform security once cross-platform support exists. |
| **B3** | Cloud-synced ciphertext still leaks metadata and timing. | Google Drive/OneDrive retain revision history of `.enc` files. An attacker with Drive access (or Google/Microsoft under legal process) sees file names, sizes, edit timestamps, and directory structure (`stripe/dev-key.enc` at 21:47) even without the DEK. | Envelope encryption protects payload confidentiality, not metadata. Enterprises evaluating this will ask; the RFC should state it rather than let it surface in a security review. |
| **B4** | The named-pipe mechanism (Pillar III, Tiers 3–4) still has a real limit even after moving to a managed, re-opened pipe. | The re-opened pipe (reopened by `jit-agent` on every new `open()`) solves tools that reopen/reread a config path — the original one-shot, self-destructing-on-EOF design didn't. It does **not** solve true random access within a single open (`stat` for real size, `lseek`, `mmap`): no FIFO can serve that on any POSIX system. `memfd_create` would, but it's Linux-only — no macOS equivalent exists in Phase 1. | Tier 3 (`.env` mount) needs authorization on top of the re-opened pipe, not just a TTL — resolved via a decoy-by-default gate rather than per-reader identity, see **B10**. Tier 4 (legacy tools) needs a short, explicitly tested allowlist (kubeconfig, `aws-cli` config) that excludes tools requiring real random access, rather than a general "legacy tool" claim; 1Password needed a full per-CLI shell-plugin architecture to cover this space well, and a pipe-based mechanism does not replicate that for free. |
| **B5** | Revocation does not retroactively protect already-shared payloads. | `jit vault revoke alex@company.com --rotate` removes future access and rotates the *stored* secret, but if `alex` exfiltrated the plaintext (or the DEK) before revocation, that copy is unaffected. | This is standard for all secret-rotation systems, but the RFC should say so explicitly rather than let "cryptographic revocation" imply retroactive protection it can't offer. |
| **B6** | Process-lineage checks (Phase 2) are an audit signal, not a sandbox boundary. | PPID/process-tree inspection is spoofable via reparenting, `setsid`, or process-name masquerading. A moderately capable attacker who already has code execution on the box can present as a trusted parent. | Phase 2 docs should call this "anomaly signal for logging/alerting," not "EDR enforcement" — the gap between those two framings is exactly what a red-team review will probe first. |
| **B7** | `jit migrate` does not scrub git history. | Rewriting a tracked `.env` file to use `jit://` pointers leaves the old plaintext value recoverable via `git log -p` / `git blame` for the life of the repository. | `jit migrate` must either refuse to run on files with uncommitted-but-tracked history without a warning, or hand the user an explicit follow-up step (e.g., pointer to `git-filter-repo`/BFG) — silently implying "migrated = safe" is misleading. |
| **B8** | Velocity/rate limiting only catches naive scraping. | An infostealer that reads one secret every 10 minutes stays under any reasonable threshold indefinitely. | Frame as raising the cost of bulk/fast exfiltration, not as a detector for patient, low-and-slow access. |
| **B9** | Biometric gating has a fallback path. | OS-level biometric APIs (Touch ID, Windows Hello) fall back to device password/PIN when biometrics are unavailable or disabled. `jit`'s guarantee is therefore "OS local-auth-bound," not strictly "biometric-bound." | State the real guarantee (bound to OS local authentication) rather than the stronger-sounding but inaccurate "biometric-bound." |
| **B10** | A continuously live-mounted `.env` pipe re-exposes the exact AI-agent/MCP threat (attack surface row 2) that pointer-rewriting was built to close. | Any process that opens the mounted `.env` path during the session TTL gets the real plaintext — including a rogue MCP server or coding agent doing a routine read for context, not only the intended dev-server process. | **Resolved, but not via reader identity — via a decoy-by-default gate.** `spike/fifo-reader-identify/FINDINGS.md` found neither candidate for gating by *identifying* the reader holds up: Apple's Endpoint Security framework (the kernel-authoritative answer) is impractical for jit's bare-binary/Homebrew distribution shape (a discretionary, indefinitely-slow entitlement that would force an app-bundle/System-Extension repackaging — evaluated and parked, not queued for later); the cheaper unprivileged `libproc` scan (`internal/lineage`) works but has a real, adversary-exploitable timing race (a reader that closes fast enough evades identification). The actual fix inverts the approach: `internal/mount.RevealState` serves `DecoyValues` by default and only serves real content during a short, explicitly-triggered window (auto-revealed on unlock/`jit migrate` refresh, or explicit `jit agent reveal`) — bounding *when* anyone gets something real, instead of trying to identify *who's* asking. `internal/lineage`'s reader identification is retained purely as a best-effort audit log (§5.1 Process Lineage Logging) layered on top, never as what decides what gets served; its `PathHeldOpen` fd-table check additionally gates one narrower, content-free decision — whether a just-served pipe needs the stale-reader isolation rename or can be reused (GAPS.md #47: needless renames fed a file-watcher re-read loop) — safe there because the identification race inverts: a reader that closes fast enough to evade the scan has, by closing, removed the lingering-fd hazard the rename guards. See GAPS.md #2 (resolved) and `internal/lineage/doc.go`. |

**Explicit non-goals for Phase 1** (stated the way bumblebee states "no package manager execution, no source-file reads"):

- jit does **not** sandbox or monitor the target process after exec — once launched, the target process's behavior is out of scope.
- jit does **not** provide network-level exfiltration prevention (DLP). It reduces what's available to steal at rest; it does not watch outbound traffic.
- jit does **not** support Windows or Linux in Phase 1 — macOS only. Windows is the intended next platform; Linux follows Windows and, per B2, ships best-effort/software-keyring-bound unless a TPM-backed Secret Service is detected.
- jit does **not** rewrite git history as part of `jit migrate`.
- jit's Phase 2 "EDR" language (Section 5.1) describes detection/alerting signals, not a sandbox or enforcement boundary equivalent to commercial EDR.
- jit does **not** have a CI/headless/non-interactive story in Phase 1. Secure Enclave/local-auth gating requires an interactive local session by design — there is no service-account-style token for build servers yet. Use your CI provider's native secret store for pipeline secrets until this is explicitly scoped.

---

## 3. Phase 1 Core Architecture (MVP Specification)

### Pillar I: Atomic, File-Per-Secret Storage — Local by Default

`jit` stores each secret as an isolated, atomic encrypted file within an intuitive directory tree. **Local storage is the Phase 1 default** — e.g. `~/Library/Application Support/jitpass/` on macOS — since it never leaves the device and so sidesteps B3 (cloud metadata/revision-history leakage) entirely, rather than accepting that tradeoff by default:

```text
~/Library/Application Support/jitpass/        # default: local-only, no sync
├── stripe/
│   ├── dev-key.enc
│   └── webhook-secret.enc
└── aws/
    └── s3-access-key.enc
```

**Cloud storage is an explicit opt-in** (`jit vault init --storage "~/Google Drive/.jit"`, not yet implemented) for developers who want multi-device access and are willing to accept B3. It's worth being honest about what that opt-in does and doesn't buy today: storing a monolithic vault database (`.db`/`.json`) in a synced folder would introduce split-brain conflicts, so `jit` keeps the file-per-secret layout even when synced — creating, updating, or revoking a secret still touches one small file, so sync across Google Workspace, OneDrive, or Dropbox is fast and (for single-device writes) conflict-free. Concurrent *creation* of the same secret path from two offline devices before sync completes is not conflict-free — last-write-wins on most consumer sync clients, so `jit` should detect and surface a conflict marker rather than silently picking a winner. And critically: syncing the encrypted file to a second machine doesn't make it *readable* there — that machine's Secure Enclave can't decrypt a DEK wrapped for a different device's key, so real multi-device access additionally depends on the Phase 2 self-share mechanism (§5.2), not on cloud storage alone. Opting into cloud storage without that piece just gets you an encrypted backup you can't yet decrypt anywhere else.

### Pillar II: Hardware-Bound Envelope Encryption (Team-Share Ready)

To support offline single-player execution today while building the cryptographic foundation for future team sharing (Phase 2), every `.enc` file implements **Envelope Encryption**:

```json
{
  "version": 1,
  "recipients": {
    "local-macbook-pro": "ENCRYPTED_DEK_HEX..."
  },
  "payload": "ENCRYPTED_SECRET_VALUE_HEX..."
}
```

- **The Mechanism:** The raw secret (`payload`) is encrypted using a unique, one-time Data Encryption Key (DEK) via `AES-256-GCM`. That DEK is wrapped using the developer's Master Encryption Key (MEK) and stored in the `recipients` block. `internal/vault`'s envelope/storage logic is written against a `KeyWrapper` interface — where and how the MEK itself is protected is a pluggable implementation behind it, not baked into the vault's own code.
- **Local-Auth Binding — target vs. current (Phase 1 interim).** The target guarantee is MEK access gated by macOS's native access control flag, `kSecAccessControlBiometricsAny` (OS-enforced: the key simply cannot be released without a passing biometric/passcode check, regardless of what code asks), backed by a real Secure Enclave key once a Developer ID signing identity is available — currently blocked on an unresolved Apple account issue. Building that requires `kSecAttrIsPermanent`-style keychain persistence, which needs the same signing identity (`-34018 errSecMissingEntitlement` under ad-hoc signing — confirmed for *any* `SecAccessControl`-gated item, not just Secure-Enclave-token keys, see `spike/keychain-interim-key/FINDINGS.md`). Until then, `internal/keychainwrap` implements `KeyWrapper` with what's actually achievable: the MEK sits in a plain (non-ACL) keychain item, and every wrap/unwrap first requires a real `LAContext.evaluatePolicy` Touch ID/passcode challenge — a genuine OS-level prompt, but enforced by jit's own code path, not by the OS refusing to release the key. Per B9, this is "prompted local authentication," a materially weaker guarantee than OS-enforced ACL or Secure Enclave binding: a determined attacker with existing code execution as this same local user could bypass the application-level check and read the keychain item directly. `internal/secureenclave` is where the target implementation lands once signing is unblocked — same `KeyWrapper` interface, no changes needed elsewhere. (Windows CNG/DPAPI-NG and Linux `pam_fprintd`/keyring unlock are Phase 2/3 platform work — see §5.5 — not part of Phase 1.)
- **Session Grace Period (`jit-agent`):** To prevent prompt fatigue during active development, an ephemeral, session-scoped Unix socket caches the decrypted MEK in memory for a configurable TTL (default: `15m`). Screensaver activation or system sleep immediately destroys the socket.

### Pillar IV: Named Profiles

CLI examples elsewhere in this RFC (`jit export --profile aws-admin`) assumed a concept Pillar I never defined. Borrowing directly from 1Password's Environments (a named, project-scoped group of key-value pairs, decoupled from the underlying vault items): a **profile** in `jit` is a small manifest file — not a vault directory — that maps environment-variable names to secret paths:

```yaml
# .jit/profiles/aws-admin.yaml
AWS_ACCESS_KEY_ID: aws/s3-access-key
AWS_SECRET_ACCESS_KEY: aws/s3-secret-key
AWS_DEFAULT_REGION: aws/default-region
```

This is distinct from, and composable with, the storage and injection mechanisms elsewhere in this RFC:

- The **vault tree** (Pillar I) is where encrypted payloads physically live, organized by owner/service, not by project.
- A **profile** is a named *view* over that tree, scoped to a project or task (`aws-admin`, `stripe-webhooks-local`) — safe to commit to git, since it contains only paths, never ciphertext or values.
- A profile can be materialized to a shell session (`jit export --profile aws-admin`) or to a mounted `.env` file (Pillar III, mechanism 2) — same manifest, different destination.

Without this file, `jit export --profile X` has no defined resolution — this manifest is what makes that command well-specified rather than aspirational.

### Pillar III: Minimal-Footprint Runtime Injection

Traditional secret daemons run continuously in the background, consuming system resources and leaving decrypted strings vulnerable to memory-scraping attacks. `jit` narrows that surface but does not eliminate it: `jit-agent`'s TTL-scoped session broker (Pillar II) is a deliberate, minimal daemon, not the "zero-footprint" absolute the original title implied. 1Password's frictionless CLI UX ("run any command, no manual unlock") only exists because its desktop app is a comparable always-on, already-unlocked broker — `jit` accepts the same trade for the same reason. A short-lived, TTL-bound broker holding a key in memory is a materially smaller target than plaintext secrets sitting on disk indefinitely, but it is a real running process, not nothing.

Four mechanisms follow, tiered by preference — each trades off footprint, compatibility, and how much cooperation the target tool needs to give:

**Tier 1 — Process Overwrite (`syscall.Exec` / `execve`), preferred whenever the launch command can be wrapped.** When executing `jit run -- npm run dev`, the CLI parses reference pointers, verifies OS local auth, and decrypts the target `.enc` files strictly in memory. Instead of spawning a child process, `jit` **replaces its own process image** with the target application runtime (`node`, `python`, `go`) — the same technique `aws-vault exec` uses. The `jit` binary itself is gone from memory the instant the application starts; the secret remains exposed to the new process per B1. `execve` is POSIX and carries over to a future Linux port unchanged; Windows has no `execve` equivalent and will need a `CreateProcess`-based redesign of this pillar when Windows work starts (§5.5) — not a drop-in port.

**Tier 2 — Native Credential Helpers, preferred whenever the target tool supports one.** Some ecosystems already have a pluggable credential-resolution protocol: AWS CLI/SDKs support `credential_process`, Kubernetes `client-go` supports exec-credential plugins. For these, `jit` ships as the helper binary itself (invoked directly by the AWS/K8s tooling per their own protocol) — no pipe, no mounted file, no `--kubeconfig` path juggling, and no filesystem surface at all. This sidesteps B4 entirely and should be used ahead of any pipe-based mechanism whenever the target tool has this hook.

**Tier 3 — Live-Mounted `.env`, the primary mechanism for `.env`-consuming apps that don't fit Tier 1 or 2.** For the "app reads `.env` itself, however it was launched" case: IDE run configs, `docker compose up` with `env_file:`, frameworks that auto-load `.env` on boot. Rewriting `.env` in place with `jit://` pointer strings only resolves for processes launched through `jit run` and silently breaks everything else (the blocker that motivated this redesign). Instead, `jit migrate` converts the file's keys into a profile manifest (Pillar IV) and replaces the physical `.env` with a named pipe at the same path. `jit-agent` services that pipe for the life of the session TTL, **re-opening it on every new `open()`** so standard dotenv loaders "just work" unmodified across repeated reads/hot-reloads. Gated per **B10** by a decoy-by-default mechanism, not reader identity: the mount serves fake-looking `DecoyValues` unless currently *revealed*, and only real values during a short window — opened automatically on every unlock/`jit migrate` refresh (the ergonomic default, so a dev server started right after either event just works), or explicitly via `jit agent reveal <path>`. `jit migrate` also best-effort wires that reveal call into whatever project-level pre-run hook already exists (an existing `.envrc`, or `package.json`'s `dev`/`start` scripts via npm's own `pre<script>` convention) so the common case needs no manual step at all — deliberately narrow, not attempted for docker-compose/Makefiles/IDE run configs, where no generic "about to run" hook exists to safely target. One incidental benefit, confirmed empirically (spike/named-pipe/, git 2.50.1): because a named pipe isn't a regular file, `git add` silently skips it — exit code 0, no warning on stdout or stderr, and it never appears in `git ls-files` or `git status`. The net effect claimed here holds (the mount point can never end up committed the way a plaintext `.env` can), but precisely stated: git doesn't *refuse* in any visible way, it just quietly does nothing. Don't build a product claim like "git will warn you" on top of this — there is no warning, only the absence of a commit.

**Tier 4 — The same managed, re-opened pipe primitive as Tier 3, scoped to a short validated allowlist for legacy tools that need a real config path** (e.g., `--kubeconfig`). This replaces the original one-shot, self-destructing-on-EOF pipe design (which broke on any tool that reopened or reread the path — see **B4**) with the same re-opened pipe Tier 3 uses, since that already solves "reopens the path." It does **not** solve true random access within a single open — `stat` for real size, `lseek`, `mmap` — which no FIFO can serve on any POSIX system, pipe-based or not. `memfd_create` solves that, but it's Linux-only; there's no macOS equivalent, so tools that need real random access are simply unsupported in Phase 1 rather than degraded, and should not be added to the allowlist. Full `memfd_create`-backed random access is a legitimate upgrade to revisit once the Linux port (§5.5) exists. Kept narrow deliberately: 1Password needed a full per-CLI shell-plugin architecture to cover this space well, and this mechanism does not replicate that — claiming broad "legacy tool" support here is the kind of gap a security review finds immediately.

---

## 4. Phase 1 Developer Workflow & CLI Reference

### Discovery & Risk Assessment (`jit audit`)

**`jit audit` is always read-only — there is no flag that makes it mutate anything.** It scans the endpoint, classifies findings, and prints or emits a report; it never touches, encrypts, or rewrites a single file on disk, under any flag combination. This is a hard command boundary, not just a default: fixing what `jit audit` finds is a separate command, `jit migrate` (below), specifically so a tool whose whole value proposition is "safe to run anytime" can't be turned into a mutating one by a single mistyped flag.

**Scan categories** — the five attack surfaces above, plus two detection-only extensions:

1. Shell configs — plaintext `export KEY=value` assignments in `.zshrc`/`.bashrc`/etc.
2. `.env` files — presence and location
3. Credential files — `~/.aws/credentials`, `~/.kube/config`, `.npmrc`, and similar, by system
4. AI tool / MCP configs — embedded secrets in `mcp.json`-family files
5. Private keys — missing passphrase, loose file permissions, keys outside expected directories
6. IaC variable files — `terraform.tfvars` and equivalents (detection only, no mitigation yet)
7. Suspicious filenames — heuristic match against known infostealer/backup-credential naming patterns (detection only)

**Two cross-cutting signals escalate risk independent of category**, adopted directly from the fleet-scale Jamf EA scanner referenced in §0: a **production-indicator match** (a `prod`/`production` token at a word boundary in a key name or visible value — matches `PROD_DB_URL`, `evm-prod-ro-endpoint`; does not match `nonprod`, `product`) and a **public IP address** (anything outside RFC 1918 private ranges) found in a visible value. Either one alone escalates a finding to Critical, regardless of total count.

**Risk levels:**

| Level | Trigger |
|---|---|
| Critical | Any production-indicator match or public IP found |
| High | Unencrypted SSH key, a loose key/cert file outside a protected directory, any shell-config plaintext export, any MCP-embedded secret, or ≥5 total findings |
| Medium | ≥3 total findings |
| Low | 1–2 total findings |
| Clean | 0 findings |

**Redaction is not optional.** Matching bumblebee's own posture on MCP `env` blocks ("parses configs for inventory but does not emit those values"), `jit audit` never prints or emits a real secret value — only file path, key name, category, risk level, and a masked preview (`sk_test_5**********`). A value that's already masked in the scanned file (e.g. `****`) is not re-flagged as a prod/IP match, matching the source script's behavior of skipping already-masked values for both detections.

**Files jit already protects are excluded from findings — visibly, never silently.** Scanners only ever read regular files: a live mount's named pipe has no at-rest content to report (and what the agent serves through it is decoy values, i.e. the protection working, not an exposure — reading it back as a finding was a real false positive on every mounted `.env`). Registered live mounts are instead counted into the summary's `jit_protected_count` and reported as an "already protected by jit" line, so a migrated file's disappearance from the findings list reads as the success it is rather than a scanner miss.

```bash
# Human-readable terminal report (default): color-coded risk banner, per-category
# counts, and exact file:line locations — no secret values printed, nothing on
# disk is touched.
jit audit

# Structured output for security pipelines: one finding record per line, using
# the same record shape as bumblebee (record_type, schema_version, scan_time,
# endpoint block) so a fleet already ingesting bumblebee NDJSON can pull jit
# audit findings through the same pipe — see §5.3. Still fully read-only.
jit audit --format ndjson
```

### Guided Migration (`jit migrate`)

A separate command from `jit audit`, not a flag on it — see the read-only note above for why. `jit migrate` re-runs the same scan `jit audit` uses internally (machine state may have changed since the last audit) and then acts on what it finds: converts `.env` keys into a profile manifest and replaces `.env` with a live mount (Pillar III, Tier 3), encrypts other discovered secrets into the vault, and sanitizes source files in place. It does **not** rewrite git history (B7) — a tracked file gets flagged with an explicit manual follow-up step instead of a silent "migrated = safe" implication.

```bash
# Preview only — prints exactly what jit migrate would do to each finding
# (moved to vault, converted to a live mount, or "detection only, manual
# fix needed" for categories 6-7) without touching a single file. This is
# the safe way to see the plan before committing to it, same convention as
# `ansible-playbook --check` / `kubectl apply --dry-run` / `npm publish --dry-run`.
jit migrate --dry-run

# Applies the plan above for real.
jit migrate
```

#### NDJSON Finding Record Schema

Two record types, emitted one per line; a run ends with exactly one `scan_summary`. The envelope fields deliberately mirror bumblebee's shape verbatim — same field names, same `endpoint` block — so a receiver already ingesting bumblebee NDJSON can add `jit audit --format ndjson` as a second source through the same pipe and join on `endpoint.device_id` with no transform step.

**Envelope (shared with bumblebee):**

| Field | Type | Notes |
|---|---|---|
| `record_type` | string | `"finding"` \| `"scan_summary"` |
| `record_id` | string \| null | Content-addressed hash of `(finding_type, file_path, key_name)`. Stable across runs, so re-scans dedupe cleanly. `null` on `scan_summary` — `run_id` is already unique per run. |
| `schema_version` | string | `"0.2.0"` — versioned independently from bumblebee's schema, same style. 0.2.0 added `scan_summary`'s `jit_protected_count` (additive). |
| `scanner_name` | string | `"jit"` |
| `scanner_version` | string | e.g. `"v0.1.0"` |
| `run_id` | string | Random per-invocation ID; every record from one `jit audit` run shares it. |
| `scan_time` | string | ISO 8601 UTC. |
| `endpoint` | object | `{hostname, os, arch, username, uid, device_id}` — identical shape to bumblebee's. `os` is always `"darwin"` while Phase 1 is macOS-only; `device_id` is `""` on an unmanaged (non-MDM) machine. |

**`finding` records add:**

| Field | Type | Notes |
|---|---|---|
| `finding_type` | enum | `shell_config_secret` \| `env_file_present` \| `credential_file` \| `mcp_embedded_secret` \| `private_key_risk` \| `iac_variable_file` \| `suspicious_filename` |
| `severity` | enum | `critical` \| `high` \| `medium` \| `low` \| `info` — this finding's own severity, forced to `critical` if `production_indicator_match` or `public_ip_match` is set, per the risk table above. |
| `file_path` | string | Absolute path. |
| `line` | int \| null | Line number where determinable. |
| `key_name` | string \| null | Env var name or credential-system name — not itself sensitive, shown in full. |
| `value_preview` | string \| null | Masked preview (`"sk_test_5**********"`). `null` when there's no associated value (e.g. `suspicious_filename`). **Never the real value** — see the redaction rule above. |
| `production_indicator_match` | boolean | |
| `public_ip_match` | string \| null | The matched IP itself — not sensitive, shown in full (unlike `value_preview`). |
| `confidence` | enum | `high` \| `medium` \| `low` |
| `evidence` | string | Short human-readable justification, e.g. `"key name matches production-indicator pattern"`. |
| `already_masked` | boolean | `true` if the source value was already redacted (e.g. `****`) before `jit` saw it — in which case it is never evaluated for `production_indicator_match`/`public_ip_match`, per the redaction rule. |

**`scan_summary` records add:**

| Field | Type | Notes |
|---|---|---|
| `total_findings` | int | |
| `findings_by_category` | object | `finding_type` → count, all seven keys always present. |
| `risk_level` | enum | `critical` \| `high` \| `medium` \| `low` \| `clean` — aggregate, same formula as the risk table above. |
| `production_indicator_count` | int | |
| `public_ip_count` | int | |
| `scan_duration_ms` | int | |
| `jit_protected_count` | int | Registered jit live mounts currently occupying their path as a named pipe — files excluded from scanning because they're already protected (content served from the encrypted vault, no plaintext at rest). Added in schema 0.2.0. |

<details>
<summary>Example: a shell-config finding escalated to critical by a production-indicator match</summary>

```json
{
  "record_type": "finding",
  "record_id": "finding:8f2c1a9b3d4e5f60",
  "schema_version": "0.2.0",
  "scanner_name": "jit",
  "scanner_version": "v0.1.0",
  "run_id": "b6d4a1e2c3f4a5b6c7d8e9f0a1b2c3d4",
  "scan_time": "2026-07-05T14:02:11.203Z",
  "endpoint": {
    "hostname": "menit-mbp",
    "os": "darwin",
    "arch": "arm64",
    "username": "menit",
    "uid": "501",
    "device_id": "MDM-3B91F0"
  },
  "finding_type": "shell_config_secret",
  "severity": "critical",
  "file_path": "/Users/alex/.zshrc",
  "line": 42,
  "key_name": "PROD_DB_URL",
  "value_preview": "postgres://ad**********",
  "production_indicator_match": true,
  "public_ip_match": null,
  "confidence": "high",
  "evidence": "key name matches production-indicator pattern (prod)",
  "already_masked": false
}
```

</details>

<details>
<summary>Example: an already-masked credential-file value, correctly not escalated</summary>

```json
{
  "record_type": "finding",
  "record_id": "finding:9c8b7a6f5e4d3c2b",
  "schema_version": "0.2.0",
  "scanner_name": "jit",
  "scanner_version": "v0.1.0",
  "run_id": "b6d4a1e2c3f4a5b6c7d8e9f0a1b2c3d4",
  "scan_time": "2026-07-05T14:02:11.588Z",
  "endpoint": {
    "hostname": "menit-mbp",
    "os": "darwin",
    "arch": "arm64",
    "username": "menit",
    "uid": "501",
    "device_id": "MDM-3B91F0"
  },
  "finding_type": "credential_file",
  "severity": "low",
  "file_path": "/Users/alex/.aws/credentials",
  "line": null,
  "key_name": "aws_secret_access_key",
  "value_preview": "****",
  "production_indicator_match": false,
  "public_ip_match": null,
  "confidence": "medium",
  "evidence": "value already masked at source; not evaluated for production/IP signals",
  "already_masked": true
}
```

</details>

<details>
<summary>Example: the closing scan_summary record</summary>

```json
{
  "record_type": "scan_summary",
  "record_id": null,
  "schema_version": "0.2.0",
  "scanner_name": "jit",
  "scanner_version": "v0.1.0",
  "run_id": "b6d4a1e2c3f4a5b6c7d8e9f0a1b2c3d4",
  "scan_time": "2026-07-05T14:02:12.881Z",
  "endpoint": {
    "hostname": "menit-mbp",
    "os": "darwin",
    "arch": "arm64",
    "username": "menit",
    "uid": "501",
    "device_id": "MDM-3B91F0"
  },
  "total_findings": 3,
  "findings_by_category": {
    "shell_config_secret": 1,
    "env_file_present": 0,
    "credential_file": 1,
    "mcp_embedded_secret": 0,
    "private_key_risk": 1,
    "iac_variable_file": 0,
    "suspicious_filename": 0
  },
  "risk_level": "critical",
  "production_indicator_count": 1,
  "public_ip_count": 0,
  "scan_duration_ms": 842,
  "jit_protected_count": 2
}
```

</details>

### Day-to-Day Operations

```bash
# Set up the local vault (generates the master encryption key).
# Defaults to local-only storage (~/Library/Application Support/jitpass) — no
# --storage flag needed unless opting into cloud sync (accepts B3, see Pillar I).
# All vault operations live under the `vault` subcommand, kept separate from
# jit's other top-level commands (audit, migrate, run, export, doctor),
# which aren't vault CRUD.
jit vault init

# Opt in to cloud-synced storage for multi-device access (accepts B3 tradeoff;
# also needs Phase 2 self-share, §5.2, before a second device can decrypt
# anything) — not yet implemented, tracked for a later Pillar I increment.
jit vault init --storage "~/Google Drive/.jit"

# Create or update a local secret. Prompts for the value with hidden input
# by default (a bare positional value works too but lands in shell history);
# --stdin reads it from a pipe for scripting instead.
jit vault set stripe/dev-key

# Read a secret manually (prompts OS local auth: Touch ID / passcode fallback)
jit vault get stripe/dev-key

# Preflight: verify every secret a profile/.env mount references actually
# resolves before handing off to the app — fails fast with a named missing
# secret instead of the app crashing on an empty env var.
jit doctor

# Execute a local development server with memory-injected secrets.
# --profile is required — it's what makes the command well-specified
# (§Pillar IV) rather than leaving "which secrets?" undefined.
jit run --profile aws-admin -- npm run dev

# Execute an MCP server securely without hardcoding API keys in mcp.json
jit run --profile aws-admin -- npx -y @modelcontextprotocol/server-github

# Inject ephemeral credentials into the current terminal session
eval "$(jit export --profile aws-admin)"
```

---

## 5. Phase 2 Roadmap: Detection Signals, Enterprise & Collaboration

*Phase 2 evolves `jit` from an isolated secret runtime into a fleet-aware detection-and-response signal source and organizational DevSecOps platform. Per B6, the capabilities below are framed as anomaly signals and audit trails, not as an enforcement sandbox — pairing `jit`'s signals with `bumblebee`'s point-in-time inventory scans gives a fleet both "is this secret being accessed weirdly" and "is this endpoint running something known-bad" without either tool overclaiming the other's job.*

### 5.1 Detection Signals & Anomaly Logging

- **Process Lineage Logging ("Who is asking?"):** Before releasing a decrypted secret, `jit` inspects its own parent process tree (`sysctl`, `/proc`, ToolHelp32) and logs/classifies the caller (trusted interactive terminal vs. unrecognized parent). Per B6, an unrecognized-parent match triggers a step-up auth challenge and an audit log entry — it is a speed bump and signal, not a guarantee against a determined local attacker who already has code execution. Confirmed early, ahead of the rest of Phase 2: `internal/lineage` (promoted from `spike/fifo-reader-identify/`) already does this for the live `.env` mount specifically, unprivileged and same-UID-only, feeding a best-effort audit log alongside B10's decoy-by-default gate — never deciding what CONTENT gets served, since the same spike found a real timing race that makes reader identity untrustworthy as a hard boundary. (Its `PathHeldOpen` variant does gate one content-free mechanical decision — pipe reuse vs. stale-reader isolation after a serve cycle, GAPS.md #47 — where that race works in jit's favor rather than against it: evading the scan requires closing the fd, which removes the hazard.)
- **Velocity Tripwires & Rate Limiting:** A sliding-window counter flags abnormal access velocity (e.g., >15 requests in 5 seconds) and can lock the local vault pending re-auth. Per B8, this raises the cost of fast/bulk scraping; it does not catch low-and-slow exfiltration.
- **Deception Engineering ("Honey-Secrets"):** `jit audit` can inject decoy credentials alongside real `jit://` pointers. `jit run` strips decoys from memory so legitimate apps never see them; any external use of a decoy value is a high-confidence compromise signal, independent of B1/B6's limits.

**Open item — event schema undefined.** §4's NDJSON finding schema covers `jit audit` output only (a versioned envelope: `record_type`, `schema_version`, `endpoint`, etc.). The three signals above have no equivalent structured, versioned shape yet — they're specified narratively here, not as a data format. That's fine while these signals stay purely local (current Phase 2 scope; telemetry shipping is deferred to a possible Future Enterprise Tier), but the schema needs to exist *before* anything downstream (a local log file, and eventually SIEM/webhook streaming per §5.3) depends on it, or it will get improvised ad hoc under time pressure instead of designed once. Default direction: reuse the §4 NDJSON envelope shape (same `record_type`/`schema_version`/`endpoint` fields) with new `record_type` values (e.g. `lineage_event`, `velocity_trip`, `honeytoken_use`) rather than inventing a second format — needs its own short design pass, not a full RFC section, before Phase 2 implementation starts on this area.

### 5.2 Collaboration & Asymmetric Team Sharing

- **Asymmetric Public/Private Key Sharing:** `jit vault share aws/prod-db --with alex@company.com` fetches the recipient's public key (X25519 / `age` protocol), encrypts the file's DEK, and appends it to the `recipients` block.
- **Cryptographic Revocation & Rotation:** `jit vault revoke alex@company.com --rotate` removes a recipient's key and rotates the underlying secret. Per B5, this is not retroactive against a copy already exfiltrated before revocation.

### 5.3 Enterprise Governance & Observability

- **SIEM & Telemetry Streaming:** Structured NDJSON audit logs (same format family as `bumblebee`'s NDJSON records, for easy co-ingestion) ship to Datadog, Splunk, CrowdStrike Falcon, or Slack/Teams webhooks for high-severity events (failed auth, blocked lineage, tripped velocity limits, canary use).
- **Enterprise Admin Console & Policy-as-Code:** A declarative `.jit-policy.yaml` deployed via MDM (Jamf, Intune) or GitOps:

```yaml
version: "2.0-preview"
enterprise:
  organization: "Enterprise Security"
  admin_console_url: "https://vault-admin.internal"
  siem_webhook: "https://telemetry.internal/api/v1/jit-events"

security_policies:
  local_auth:
    require_for_decryption: true
    session_ttl_minutes: 15
    allow_new_credential_registration: false # anti-tamper

  anomaly_detection:
    velocity_limit:
      max_requests: 12
      window_seconds: 60
      action_on_breach: "LOCK_AND_ALERT"

    process_lineage:
      mode: "audit_and_challenge"   # not "enforce" — see B6
      trusted_parents:
        - "iTerm2"
        - "Code - Insiders"
        - "Cursor"
        - "zsh"
      flagged_parents:
        - "python3"
        - "curl"
        - "sh"

  deception:
    inject_canary_tokens: true
    canary_types:
      - "aws_iam"
      - "stripe_api"
    auto_refresh_days: 30

  # Exploratory — not committed, see 5.4.
  # scheduled_checks:
  #   enabled: false
  #   audit_interval: "24h"
  #   integrity_check_interval: "1h"
  #   on_finding: "LOG_AND_ALERT"
```

### 5.4 Scheduled Local Checks (Exploratory — not committed)

Idea to revisit later, not scoped for Phase 1 or current Phase 2 commitments: a config-level hook for periodic, unattended runs of checks that today only happen on-demand — e.g., re-running `jit audit` to catch newly introduced plaintext secrets, verifying vault/recipient integrity, or flagging secrets past a staleness threshold. Bumblebee deliberately keeps cadence external (cron/launchd/systemd own scheduling, the binary just does one scan and exits); the open question for `jit` is whether scheduling belongs in the same place (external runner) or as a first-class config block like the commented-out `scheduled_checks` stub above, given that a background scheduled process reintroduces some of the "daemon" surface Pillar III is designed to avoid (see B1/B6 — a scheduled check that touches the vault outside an interactive session needs its own lineage/auth story). Needs its own design pass before committing to either shape.

### 5.5 Platform Expansion: Windows, then Linux

Sequenced, not parallel — each platform ships only after the prior one is validated in real usage:

1. **Windows (next).** Hardware-bound MEK via TPM 2.0 / CNG-DPAPI-NG, local auth via Windows Hello with device-PIN fallback (B9 applies identically). Pillar III's process-replacement mechanism needs a `CreateProcess`-based redesign, not a port — Windows has no `execve` equivalent (see §3, Pillar III). Scope this as its own design pass rather than assuming the macOS implementation generalizes.
2. **Linux (after Windows).** Best-effort per B2: hardware-bound only on the minority of dev laptops with a TPM-backed Secret Service, software-keyring-bound (gnome-keyring/kwallet) otherwise. Ship with the guarantee level surfaced to the user (e.g., `jit status` reporting `hardware-bound` vs. `os-keyring-bound`) rather than presenting a uniform security claim across distros.

Until Windows and Linux ship, every claim elsewhere in this RFC (Sections 1–4) should be read as macOS-only.
