# Spike Findings: Named-Pipe Re-Open Mechanism (Tier 3 live `.env` mount)

**Question:** does the "re-open the FIFO on every new `open()`" pattern (RFC.md Pillar III Tier 3, boundary B4) actually work reliably for sequential readers, the way standard dotenv loaders and hot-reloading tools would exercise it?

**Environment:** macOS 26.5.1, arm64, Go 1.26.4, git 2.50.1 (Apple Git-155).

## Result: re-open loop confirmed solid

A server loop that does `open(path, O_WRONLY)` (blocks until a reader appears) → write → close → immediately loop back, successfully served 4 sequential readers with no deadlocks or stale data:

| Reader | Timing | Result |
|---|---|---|
| 1 | Immediate, right after FIFO confirmed to exist | Correct content, 69ms wait |
| 2 | After a 0.5s pause (simulating a later hot-reload) | Correct content, 526ms wait |
| 3 | Immediately back-to-back, no pause | Correct content, 11ms wait |
| 4 | After a 0.2s pause | Correct content, 222ms wait |

No reader got stale data, an empty read, or hung. The pattern is sound for the common case (one reader opens, reads to EOF, closes; the next reader repeats).

## Real requirement surfaced: don't launch the target app until the FIFO exists

An early, sloppier version of this test had a reader (`cat`) attempt to open the path before the server had finished `mkfifo`, and got `No such file or directory`. Fixed by polling for `[ -p "$FIFO" ]` before proceeding. **This is a real implementation requirement for jit, not just a test-harness bug:** whatever creates the mount (`jit migrate`, `jit run`) must confirm the FIFO exists on disk *before* launching or handing control to the target process — otherwise the very first read from a fast-starting app can race the mount setup and fail with a confusing "file not found," which is exactly the kind of silent/confusing failure the project's fail-safe-and-loud principle is meant to prevent. `jit doctor` should probably check for this too.

## Correction to RFC.md: git doesn't "refuse" to track a FIFO — it silently skips it

RFC.md originally claimed "git add refuses to track it." Verified directly (git 2.50.1):

```
$ mkfifo .env
$ git add -v .env
$ echo $?
0
$ git ls-files
(nothing)
```

`git add` on a FIFO exits `0` with **zero output on stdout or stderr**, and the file never enters the index. The net security property RFC.md cares about still holds — the mount point can never accidentally end up committed — but the mechanism is a **silent no-op**, not a visible refusal. RFC.md has been corrected to state this precisely: don't build any future product messaging on an assumption that "git will warn you," because it won't.

## How to reproduce

```bash
cd spike/named-pipe
go build -o named-pipe-spike .
./run_test.sh
```
