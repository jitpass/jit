# Spike Findings: Run-Scoped Reveal Grants (PID-tree-gated mount content)

**Question:** Can the agent serve REAL mount content only to a specific run's
process tree — grant registered by `jit run` pre-exec, gated per FIFO
rendezvous, torn down the moment the run exits — using only unprivileged,
same-UID mechanisms (no Endpoint Security, no root)? Four sub-questions, all
tested empirically. Full code in `main.go` (`-mode watch` and `-mode gate`).

**Environment:** macOS 26.5 (Darwin 25.5.0), arm64, Go 1.26.5, CGo enabled.

## 1. kqueue `EVFILT_PROC`/`NOTE_EXIT` across execve — works, and fast

`jit run` execve()s the target, keeping its PID; the grant must die when that
PID exits. Tested a child shaped exactly like that (`sh -c 'exec sleep 0.4'`):

- A watch registered **before** the exec survived it and delivered
  `NOTE_EXIT` ~1ms after actual exit, with the exit status in `ev.Data`.
  2/2 runs.
- Bonus robustness: the child exec'd **twice** (this macOS's `/bin/sh` is
  bash which then exec'd sleep — comm went `sh` → `bash` → `sleep`), each
  exec surfacing a `NOTE_EXEC`; the watch survived both. Multiple execs are
  a real shape (`jit run` → shell wrapper → interpreter) and are handled for
  free.
- Registering on an **already-exec'd** PID also delivers `NOTE_EXIT` — both
  orderings of "RPC lands" vs "target execs" are safe.
- `proc_bsdinfo.pbi_start_tvsec/usec` was **byte-stable across both execs**
  (same fork-time stamp). Recording it at grant time and re-checking at gate
  time is a valid, cheap PID-reuse tiebreaker: a recycled PID cannot have
  the same start time.

Note: spike/fifo-reader-identify's rejection of kqueue was specifically
`EVFILT_VNODE` for *reader identity* (carries no process identity — still
true). `EVFILT_PROC` for *exit tracking of an already-known PID* is a
different, valid use; no conflict.

## 2. Per-rendezvous ancestry gate — 5/5 scenarios correct

Writer-side gate at each blocking-`open()` rendezvous: enumerate **all**
same-UID processes holding the FIFO (`proc_listpids` → `PROC_PIDLISTFDS` →
`PROC_PIDFDVNODEPATHINFO`, matching path + `VFIFO` — the prior spike's scan,
extended to not stop at the first match), then walk each holder's
`pbi_ppid` chain (capped at 64 hops); serve REAL only if there is at least
one holder and **every** holder's ancestry contains the grant-root PID.

| scenario | holders seen | served | correct |
|---|---|---|---|
| depth-1 child (root → cat) | 1, in-tree | REAL | ✓ |
| depth-3 descendant (root → sh → sh → cat) | 1, in-tree | REAL | ✓ |
| out-of-tree stranger (sibling of root) | 1, out | DECOY | ✓ |
| orphaned descendant (parent exited, reparented) | 1, out | DECOY | ✓ |
| mixed concurrent (in-tree + stranger attached at once) | **2, mixed** | DECOY | ✓ |

The mixed-concurrent row is the important one: **one rendezvous does see
every attached holder**, so the fail-closed "all holders in-tree" rule is
enforceable, not just aspirational. This is strictly stronger than the
existing single-reader identification (which reports one reader and moves
on).

## 3. Orphaned descendants fail closed — accepted limitation

A granted tree that backgrounds a reader and lets its parent exit
(`( cat fifo & )`) gets DECOY: reparenting (to launchd) breaks the ppid
chain. This is the correct failure direction (no exposure, availability
only) and matches how jit run's real targets behave — `run_all_exports.sh`
style scripts run their readers synchronously, keeping the chain intact.
Double-fork daemons that outlive the run are exactly what the grant should
NOT cover anyway (the run is over).

## 4. Process-group fallback — REJECTED by evidence

The idea of using `pbi_pgid` to catch orphans was tested observationally and
failed the other way: **every process in the gate test — including the
out-of-tree stranger — shared one pgid** (children spawned from the same job
inherit it; the orphan also kept it after reparenting). A pgid gate would
have classified the stranger as granted. False-authorize beats
false-decoy, so pgid is disqualified as a gating signal. Ancestry only.

## 5. Cost

Scan + classify per rendezvous: 4.8–28ms (first call ~28ms cold, steady
state 5–7ms; the full-PID-table fd enumeration dominates, ancestry walk is
noise). Acceptable for the dominant pattern (dotenv read at process start),
but NOT for read storms — production must (a) run the gate scan only while
a grant is actually active for that mount (no grant → existing decoy/reveal
path untouched, zero new cost), and (b) cache positive per-PID verdicts for
~2s so a storming reader doesn't pay 5ms per read (same motivation as the
existing lineageScanMinGap, which the gate must bypass for correctness but
can amortize via the cache).

## Security notes (for the implementation's doc comments)

- **Residual piggyback race, inherited and disclosed:** a reader whose
  `open()` completes after the holder scan but before the write/close can
  receive the REAL payload unclassified. Same race class
  spike/fifo-reader-identify documented; the doctrine holds because the
  grant only ever *narrows* an exposure the accepted baseline (post-unlock
  floor window, hook-triggered reveals) grants to every process for 60s
  flat. Worst-case adversary outcome under a grant ≤ baseline.
- **Fail-closed everywhere:** libproc errors, fd-buffer overflow, ancestry
  walk hitting a dead parent mid-walk, zero holders found — all serve
  decoy. Failure degrades availability, never confidentiality.
- **PID reuse:** grant teardown is event-driven (~1ms after exit via
  `NOTE_EXIT`); belt-and-braces, the gate should also compare the grant
  root's recorded `pbi_start` before trusting any ancestry hit on it.
- **Same-UID boundary:** all mechanisms EPERM against other users' — the
  scan sees exactly the same-user threat surface RFC.md B10 targets, nothing
  more (unchanged from the prior spike).

## Bottom line

Run-scoped grants are **feasible with existing, already-spiked machinery
plus one new primitive (EVFILT_PROC exit watch), all unprivileged**:
grant = {root PID, start time, mount set, hard cap}; gate = full-holder
enumeration + ancestry walk, all-holders-in-tree-or-decoy; teardown =
NOTE_EXIT (primary), agent lock, shutdown, hard cap (safety net). No
Endpoint Security, no packaging change, no plaintext at rest, and the
existing decoy-by-default path is untouched whenever no grant is active.

## How to reproduce

```bash
cd spike/run-scoped-grant
CGO_ENABLED=1 go build -o grant-spike .
./grant-spike -mode watch   # exec-survival + start-time stability
./grant-spike -mode gate    # 5 gating scenarios, prints per-scenario verdicts
```
