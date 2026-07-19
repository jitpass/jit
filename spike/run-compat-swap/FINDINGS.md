# Spike Findings: Compatibility Swap (FIFO ↔ pointer file during jit run)

**Question:** Can jit make a migrated `.env` pass regular-file guards
(`[ -f ]`, `Path.is_file()`) and survive re-reads (`source`, dotenv) *while
a run executes*, then restore the decoy FIFO the instant the run exits —
without ever putting a secret on disk, without a window where the path is
missing, and without stranding a reader mid-read? Six mechanical questions,
all tested empirically. Code in `main.go` (`-mode atomicity|blocked|hardlink|
crash|refcount|inertness|all`).

**Environment:** macOS 26.5 (Darwin 25.5.0), arm64, Go 1.26.5, CGo enabled.

## The core tension the spike found — and resolved

The swap-in (FIFO → regular file) has two properties we want, and the two
obvious orderings each give only ONE:

| ordering | path ever absent? | rescues a reader blocked in open()? |
|---|---|---|
| aside-then-write (RetireFIFO's) | **yes, ~34% of samples** | yes |
| atomic rename-over | **never (0)** | **no — stranded** |

Both failures are real and reproduced:
- Aside-then-write (`rename fifo aside; write file`) leaves the path ABSENT
  between the two steps — 34,470 of ~97k concurrent stat samples saw no
  file. A `[ -f .env ]` landing there fails "not found", reintroducing the
  exact trap intermittently. **Disqualified for the swap** (it's correct for
  `jit unmount`, which is permanent and where rescue matters more than a
  one-off absent blip).
- Plain atomic rename-over never leaves the path absent, but unlinks the
  FIFO vnode with nothing kept reachable, so a reader already blocked in
  `open(O_RDONLY)` at the swap instant hangs forever (confirmed: still stuck
  2s later, had to be killed).

**Resolution — hardlink-rescue atomic swap (`swapHardlinkRescue`): both
properties at once.**
1. `link(path, path+".jit-prev")` — a second name for the same FIFO vnode.
2. `write pointerfile → path+".jit-tmp"`; `rename(tmp, path)` — atomic, so
   the path resolves to fifo-then-regular, NEVER absent.
3. `open(prev, O_WRONLY|O_NONBLOCK)` completes any blocked reader's open
   (reachable via the hardlink even though the path no longer names the
   fifo), write the pointer bytes as the handoff, close, unlink `prev`.

Result: **300 round-trips, path never absent AND the blocked reader was
released** — and it received the pointer content, not a bare EOF. This is
the primitive to build. Restore (regular → FIFO at run exit) is plain
atomic rename-over (`mkfifo tmp; rename over`), which the spike already
showed is absent-free and has no blocked-reader case (readers of a regular
file never block in open()).

## The other four, all green

- **Crash reconciliation with provenance:** the agent may recreate a FIFO
  over a leftover regular file at a mount path ONLY when that file is jit's
  own pointer file (header marker `# jit: secrets live in the vault`). A
  file a user restored by hand (`API_KEY=...`) fails the marker check and is
  left intact — surfaced, never clobbered. Both cases behaved correctly.
  This is also the startup-reconciliation gap the grant work already
  flagged: with the swap, a crash mid-run leaves a HARMLESS pointer file
  (no secret), so reconciliation is pure availability repair.
- **Refcount for concurrent runs:** 20 overlapping runs on one mount →
  exactly 1 filesystem swap-in (on 0→1) and 1 restore (on 1→0), never a
  swap mid-flight, final count 0. Concurrent `jit run`s on the same project
  are safe: the FIFO returns only after the LAST run exits.
- **Inertness of the comment-only pointer file:** `[ -f ]` and `[ -r ]`
  both pass; `set -a; . .env; set +a` sets NO variable (comments parse to
  nothing). So the file simultaneously defeats the regular-file guard AND
  cannot feed a clobbering loader — one format, both traps closed. (bash
  tested directly; python-dotenv / node dotenv parse `#` lines as comments
  by the same rule.)

## Security properties (for the implementation's doc comments)

- **No secret ever on disk.** The swapped-in file is comment pointers only;
  real values reach the run through env injection (jit run) exactly as
  today. A crash leaves a harmless pointer file, not plaintext — strictly
  better at-rest posture than the decoy FIFO even, which has none anyway.
- **Tripwire preserved for idle time.** The FIFO+decoy is the default
  posture; the swap is only in effect DURING a jit run, scoped by the same
  refcount+teardown the grant uses. Outside a run, every read is still
  decoy-served and lineage-logged.
- **Provenance-gated reconciliation** never overwrites a user's file:
  fail-safe direction is "leave it and surface", never "clobber".

## Bottom line

The compatibility swap is feasible and clean, built entirely from existing
mechanics plus one new primitive (`swapHardlinkRescue`): hardlink-rescue
atomic swap in, atomic rename-over restore, provenance-gated crash
reconciliation, refcounted for concurrent runs. It removes the regular-file
guard trap and the clobber trap TOGETHER, with no plaintext at rest and no
absent-path window. The FIFO+decoy design is retained wholesale as the
idle-time default and as `jit run --live` for file-value readers (docker
compose `env_file:` etc.); the swap is the default `jit run` behavior for
the overwhelming majority (shell scripts, dotenv loaders, guards).

## How to reproduce

```bash
cd spike/run-compat-swap
CGO_ENABLED=1 go build -o swap-spike .
./swap-spike -mode all        # or: atomicity | blocked | hardlink | crash | refcount | inertness
```
