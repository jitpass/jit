# Spike Findings: Identifying a FIFO's Reader (GAPS.md #2 / RFC.md B10)

**Question:** RFC.md B10 requires the live `.env` mount to be gated per-reader by process lineage before it's a strict upgrade over the pointer-rewrite baseline it replaces. Two candidate mechanisms were on the table: (1) a cheap, unprivileged userspace scan via `libproc`, untested; (2) Apple's Endpoint Security framework, the "correct" kernel-level answer. This spike tests both: can `libproc` actually identify a FIFO reader's PID from an ordinary, unprivileged, same-user process — and separately, is Endpoint Security even a realistic path for a solo-developer, Homebrew-distributed CLI tool?

**Environment:** macOS 26.5.1, arm64, Go 1.26.4, CGo enabled.

## Part 1: `libproc` FIFO-reader identification — works, with a real and a false race

**Mechanism:** `proc_listpids(PROC_ALL_PIDS)` → for each PID, `proc_pidinfo(PROC_PIDLISTFDS)` → for each vnode fd, `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`, matching on resolved path + `vi_type == VFIFO`. Full code in `main.go`.

### Result: accurate and fast for the common case — a reader that's still attached when scanned

Five isolated single-reader runs (fresh server per run, one reader that opens, blocks on `read()`, receives the payload, closes): **5/5 correct PID matches**, scan latency 40µs–420µs. `fi_openflags=0x1` (`FREAD`) on every match, confirming the scan is finding the read side, not an artifact.

### Confirmed: unprivileged, same-UID-only — the permission boundary is exactly what jit's threat model needs

`proc_pidinfo`/`proc_pidfdinfo` calls against other users'/root's processes failed with `EPERM` (errno tally showed a consistent ~250–460 "operation not permitted" results out of ~700 total system PIDs, every run, no `sudo`). This is the right shape for jit: it can see everything running **as the same user** — exactly the rogue-MCP-server/background-script threat RFC.md B10 is about — and nothing else. No root, no special entitlement, no elevated privilege needed for this half of the picture.

### Real, reproducible race: a reader that opens, doesn't read, and closes immediately evades identification

Using `-mode noread-reader` (opens `O_RDONLY`, then closes without calling `read()` — deliberately adversarial): **3/3 runs, the reader vanished from the process table before the scan (11ms–90ms) could find it.** The subsequent `write()` then failed with `EPIPE` ("broken pipe"), matching `internal/mount`'s existing non-fatal `onError` convention.

**This race does not, on its own, leak the secret.** In the current design (scan happens immediately after the writer's blocking `open()` returns, *before* any content is written), an evading reader that closes before classification also never received any data — the same race that defeats identification also prevents delivery. The real security question this leaves open is narrower than "can an attacker read the secret without being seen": it's "can jit reliably log *every* touch of the mount for an audit trail," and the answer there is no — a fast enough reader can touch the pipe (get `ENODATA`/nothing, or an empty read) and vanish unclassified. Given RFC.md B6 already frames process-lineage classification as "a speed bump and signal, not a guarantee against a determined local attacker" (spoofing lineage by being/spawning-from a trusted parent is unaddressed regardless), this fits the same honesty bar, not a new category of weakness.

### Unrelated artifact found, not a flaw in the identification mechanism: rapid re-open cycling produces "phantom" empty opens

Running the server through 3–5 re-open iterations back-to-back (immediately reopening `O_WRONLY` after each close) produced 1–2 iterations per run where the writer's `open()` unblocked, the scan legitimately found no reader, and the write got `EPIPE` — with no corresponding reader process in the log at all. Isolated single-iteration runs (fresh server + fresh FIFO per cycle) never showed this: 5/5 clean. This points to the same class of transient reader-count race `internal/mount`'s own doc.go and `TestServeContinuesAfterReaderClosesEarly` already document and treat as non-fatal (log-and-continue, never abort the loop) — not a new problem introduced by adding a scan, and not something this spike needed to fully root-cause given the real code already has the correct handling convention for it.

## Part 2: Endpoint Security framework — not a realistic path for jit as currently shaped

Researched separately (Apple developer forums, Objective-See/Patrick Wardle's writeups, Michael Tsai's aggregation, Santa/mitmproxy's real deployment experience — see citations below). Summary:

1. **`com.apple.developer.endpoint-security.client` is a discretionary, Apple-reviewed "restricted entitlement,"** never self-service, granted per-Team-ID in two separate stages (development, then a *separately requestable* Developer-ID-distribution stage that can be denied even after dev access is approved, no appeal). Requires a paid Developer Program membership at minimum; a free "Personal Team" cannot get it at all. Not eligible for Mac App Store distribution under any circumstance.
2. **Lead time has no SLA and Apple's own DTS staff say they have no visibility into the queue.** First-hand developer reports range from 2 weeks to 13+ months, with multiple reports of a full year of silence (no approval, no denial, no explanation).
3. **Packaging is very likely incompatible with jit's current distribution shape.** SIP-enabled machines require the entitlement to be authorized via a provisioning profile, which needs an `.app`-bundle-shaped structure (`Contents/embedded.provisionprofile`) — not a bare CLI binary. A real System Extension additionally requires activation from a host `.app` in `/Applications`, a user-facing System Settings approval (often a restart), and commonly a *separate* Full Disk Access grant. This is exactly why Google's Santa (the most mature open-source ES-based tool) ships as a signed `.pkg` installer rather than via Homebrew, and why mitmproxy's Homebrew-cask ES integration has open, reproducible activation-failure bug reports.
4. **Local prototyping is possible but doesn't generalize to real users:** disabling SIP + self-claiming the entitlement + ad-hoc signing works on a dev machine only; a SIP-enabled end-user machine rejects the self-claimed entitlement outright, and notarization can't legitimize it.
5. **No lighter alternative exists that gives both process identity and a redistributable-product-safe mechanism:** `kqueue`/`EVFILT_VNODE` carries no process identity at all (confirmed against XNU source, a hard dead end, not just an inconvenience); `fs_usage`/DTrace are root-only/interactive-debugging-only and DTrace is unreliable on Apple Silicon; the BSM audit subsystem has real process identity but is disabled by default since macOS Sonoma and is being removed by Apple; kernel extensions are Apple-discouraged and carry their own heavy Recovery-Mode/reduced-security requirements.

## Bottom line for GAPS.md #2 / RFC.md B10

- **Endpoint Security should not be treated as "the eventually-correct answer, just waiting on a slow queue."** It very likely requires jit to change its entire distribution model (bare binary + Homebrew → signed `.app` + `.pkg`, plus a first-launch System Settings approval flow) before the entitlement is even useful once granted — that's a deliberate product decision the user needs to make, not a background task to kick off quietly. Recommend treating this as parked, not queued, until/unless jit's distribution shape is already changing for other reasons.
- **The `libproc` scan is real and cheap enough to use as a best-effort classification/logging signal** (RFC.md §5.1's "Process Lineage Logging — who is asking?" bucket) — same-UID-only by construction, sub-millisecond in the common case. It should **not** be sold as a hard security gate on its own: a reader that opens and closes fast enough evades classification (though, per the analysis above, without actually receiving the secret in that same race), and lineage-spoofing by a same-user attacker is an orthogonal, unsolved limitation RFC.md B6 already discloses.
- This reinforces rather than replaces the decoy-by-default / narrow-reveal-window design direction discussed for the mount: it doesn't depend on identifying the reader at all, so it isn't subject to either Endpoint Security's packaging problem or the scan-race's classification gap. `libproc`-based lineage logging is a reasonable, low-cost *addition* on top of that — an audit trail, not the gate itself.

## How to reproduce

```bash
cd spike/fifo-reader-identify
CGO_ENABLED=1 go build -o fifo-reader-spike .
FIFO=/tmp/jit-fifo-test
rm -f "$FIFO"
./fifo-reader-spike -mode server -path "$FIFO" -iterations 1 &
sleep 0.3
./fifo-reader-spike -mode reader -path "$FIFO"        # normal case: correctly identified
# or:
./fifo-reader-spike -mode noread-reader -path "$FIFO"  # adversarial case: not identified in time
```

## Citations (Endpoint Security research)

Apple Developer Forums threads 655467, 698942, 700725, 759149, 714768, 133494, 733491, 712570, 820718, 816046, 125508, 129007, 117707, 117837, 768576; eclecticlight.co ("Explainer: entitlements and their approval," Mar 2025; SIP reference, Aug 2024); mjtsai.com/blog/2020/11/23 (EndpointSecurity approval aggregation); objective-see.org/blog/blog_0x47.html, blog_0x48.html (Patrick Wardle); elastic.co Mac system extensions blog; northpole.dev Santa deployment docs; github.com/mitmproxy/mitmproxy issue #7419; github.com/apple/darwin-xnu `bsd/sys/event.h`.
