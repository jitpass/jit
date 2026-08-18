# Spike Findings: proc_listpidspath(3) as a cheaper FIFO-reader scan

**Question:** The audit-attribution work (PRs #83-#85) left one open lead: `proc_listpidspath` — one libproc call answering "which pids have this path open" — might replace `internal/lineage`'s enumerate-every-pid fd-table walk, shrinking the reader scan enough to relax the serve path's 2s per-mount rate limit (`lineageScanMinGap`). Is it actually cheaper, and does it see FIFO holders at all?

**Environment:** macOS 26.5.0 (dev VM, 4 cores), arm64, Go 1.26.6, CGo enabled. Measured 2026-08-18.

## Result: functionally correct, ~14x SLOWER — dead end, keep the walk

With a real `cat` blocked reading a FIFO and this process holding the write end:

```
proc_listpidspath found: [writer, reader]   (reader found: true)
full walk found:         [reader, writer]   (reader found: true)

per-scan average (50 iterations):
proc_listpidspath: 42.1ms
full walk:         3.0ms
```

Consistent across runs (39.9ms vs 2.8ms on a second pass). Both approaches find both holders once the path is symlink-resolved (`/var` → `/private/var` — the fd table reports the resolved spelling, the same normalization `resolveTarget` already does in production).

## Why it's slower

This confirms the suspicion from Apple's Libc source rather than contradicting it: `proc_listpidspath` is implemented in **userspace**, inside libproc, as its own enumerate-all-pids loop — there is no kernel shortcut to inherit. And its loop does strictly more work than ours per pid: it inspects every fd type plus each process's text/cwd/root vnodes with full path resolution, where `internal/lineage` looks only at vnode-type fds and bails on everything else. The convenience call is the same walk with more baggage.

## Two incidental observations

- `proc_listpidspath` reports **both ends** of the pipe (it matched this process's write fd too). Any use would still need a per-pid fd inspection to tell read-side holders from the writer — the exact code it was supposed to replace.
- The full walk's ~3ms average here (a quiet VM, ~400 visible pids) is consistent with the ~6ms/scan implied by the 63-CPU-minute incident on a loaded machine (`internal/cli/mountmanager.go`'s rate-limit comment).

## Bottom line

- **Do not adopt `proc_listpidspath`.** The existing walk in `internal/lineage` is the faster primitive, by an order of magnitude.
- **The rate limit stays.** The scan cost that motivated `lineageScanMinGap` is real and unimprovable by this route; the shipped mitigation — the targeted one-pid `PIDHoldsFIFO` fast check with the service-wide recent-readers list (PR #85) — is the right shape: microseconds on the hot path, the full walk only when the fast path misses.

## How to reproduce

```bash
cd spike/listpidspath
CGO_ENABLED=1 go build -o spike .
./spike -iterations 50
```
