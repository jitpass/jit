# Spike Findings: Unix Socket Peer-Credential Verification

**Question:** can `jit-agent` verify the UID and PID of whatever process is connecting to its Unix domain socket, before releasing anything from the session cache?

**Environment:** macOS 26.5.1, arm64, Go 1.26.4.

## Result: confirmed working, both UID and PID

Darwin doesn't have Linux's single-call `SO_PEERCRED`/`ucred` (uid+gid+pid together) — it splits this into two separate `getsockopt` calls, both present in `golang.org/x/sys/unix`:

- `unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)` → `*unix.Xucred{Version, Uid, Ngroups, Groups}` (no PID field — Darwin's `xucred` struct doesn't carry one, unlike Linux's `ucred`).
- `unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)` → the peer's PID directly. This is a Darwin-only extension (`LOCAL_PEERPID`, not part of POSIX or Linux) — worth remembering if this code path is ever mechanically ported to Linux for the Phase 3 platform work (RFC §5.5), since Linux gets both uid and pid from `SO_PEERCRED` in one call instead of two.

Verified against ground truth: the client independently reported its own `pid`/`uid` over the connection, and the server-side `LOCAL_PEERCRED`/`LOCAL_PEERPID` values matched exactly (uid 502, pid 90136 in the test run).

## Implication for `jit-agent`

This confirms the socket-level access-control design in TECH_STACK.md §2.6 is buildable as specified: on accepting a connection, get the raw fd via `(*net.UnixConn).SyscallConn()` + `Control()`, then check `LOCAL_PEERCRED`'s uid matches `os.Getuid()` before doing anything else. `LOCAL_PEERPID` is available too, useful later for Phase 2's process-lineage classification (RFC §5.1) without needing a separate lookup.

## How to reproduce

```bash
cd spike/unix-socket-peercred
go build -o peercred-spike .
SOCK=/tmp/jit-spike-agent.sock
./peercred-spike -mode server -path "$SOCK" &
sleep 0.3
./peercred-spike -mode client -path "$SOCK"
```
