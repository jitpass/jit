# Service reliability: demand-spawned lifecycle, honest health, a broker that keeps its promises

**Status: proposed, 2026-08-17. Drafted from a full review of the
service surface (three parallel code reviews over `internal/agent`,
`internal/cli/agent*.go` and the log/history/status surfaces, 43
findings) plus a verified production incident. Nothing here is
implemented yet.**

## The incident that forced this

2026-08-17, real hardware, after `brew upgrade` moved the cask from
0.96.0 to 0.97.0: the running agent detected the binary swap and
self-retired as designed (`internal/cli/agent.go:280`), and launchd
never respawned it. The broker was dead for 71 minutes. `jit service
restart`, the documented fix, ran bootout+bootstrap, reported success
(exit 0, audit `success: true`), and fixed nothing.

Controlled experiments on the same machine established the mechanism:

| What jit relies on | launchd state | Result |
|---|---|---|
| `bootstrap` + RunAtLoad (`jit service restart`) | `runs = 0`, `pended nondemand spawn = speculative` | never spawned (30s+, twice) |
| clean exit + KeepAlive (self-retire hand-off) | `pended nondemand spawn = inefficient`, last exit 0 | never respawned (60s) |
| `launchctl kickstart` (an explicit demand) | `runs = 1` | immediate, 3 of 3 |

launchd may defer every non-demand spawn indefinitely. `kickstart` is
the only verb that creates a demand, and jit stopped using it on
2026-07-20: `1e5d43e` added kickstart-with-bootstrap-fallback, and
`660ce2c` (same day, a review-findings batch) replaced it with
unconditional bootout+bootstrap. Since then `jit service restart`
against a HEALTHY service is worse than a no-op on a deferral-prone
launchd: it boots the working agent out, re-registers the job, and the
respawn may never come. The plist declares no `Sockets` key, so there
is no demand-launch path at all; a pended non-demand spawn is the only
way the service ever starts.

The four self-retire respawns before the incident took 2s, 3s, 14s and
2m9s: the same deferral, eventually honored. "It worked before" was
survivorship.

## Guarantees this plan makes

1. **Every spawn jit asks for is a demand.** No code path registers a
   job and hopes RunAtLoad or KeepAlive fires. Bootstrap is followed by
   kickstart; self-retire IS a kickstart.
2. **No surface reports a state it has not verified.** "Restarted"
   means the socket answered AND the build matches; a timeout is a
   non-zero exit and an audit failure; health advice distinguishes what
   launchd actually reports.
3. **The service log carries signal.** A permanently failing mount
   logs its failure once per transition, not once per unlock; the
   rendered view collapses and colors what the raw log cannot.
4. **Version skew fails closed on the socket, as it already does in
   the vault.** A security field an old peer would silently drop is a
   refusal, not a silent downgrade.

## Phase 1: lifecycle correctness (the incident fix)

**D1. `reloadAgentService` kickstarts after a successful bootstrap.**
`launchctlRun("kickstart", agentServiceTarget())`, best-effort: its
error is ignored the way bootout's is, because in the healthy case
RunAtLoad may already have spawned the process and kickstart then
reports it running. Never `-k` here (it would kill the just-spawned
process). The exit-113 "Could not find service" that motivated
dropping kickstart in `660ce2c` cannot recur: the job was registered
by the bootstrap one line earlier. Living inside `reloadAgentService`
covers every caller (restart, ttl, consent, first-use install) by
construction.

**D2. Self-retire becomes a demand.** `watchOwnBinary`'s restart
callback runs `launchctl kickstart -k` on the agent's own label
instead of exiting and trusting KeepAlive. `-k` is correct here: the
service is running (so it is bootstrapped; no exit-113) and the point
is to replace it. launchd kills this process and spawns the new
binary, re-reading the plist, so an upgraded `--ttl`/`--consent`
takes effect. If the kickstart call itself errors, fall back to
today's clean exit (KeepAlive remains the backstop). The quiescent
and ppid==1 gates are unchanged.

**D3. Success means the right build answered.** `waitForAgentSocket`
is replaced by `waitForAgentBuild(root, build, timeout)`: poll
OpStatus until `st.Build == agent.BuildID()`, not until a bare dial
succeeds. This closes the lie where restart declares victory on the
OLD process still draining its shutdown, and status contradicts it
seconds later. The timeout becomes a package var so tests do not burn
real 5s waits (the 4-CPU VM flakes on exactly that).

**D4. Timeouts are failures.** Every branch that today prints "still
starting up" and returns nil instead returns an error (non-zero exit,
audit records failure): restart's three branches
(`agent.go:788,820,837`), `jit service ttl` (`:373`). `jit service
consent on|off` stops discarding the `running` result (`:486-493`);
it is a Touch ID gated security toggle that currently prints "The
service restarted" unconditionally. `jit upgrade`'s
`restartServiceOntoCurrentBinary` (upgrade.go:524-558) gets the same
verified wait; the upgrade path is the exact trigger of the incident.
`migratesummary.go:278` stays soft (best-effort context, the migrate
already succeeded) but adopts the shared phrasing. All new/changed
strings go through a preview script before implementation (list in
Phase 2).

**D5. Foreground `jit service run` refuses to steal a live socket.**
Before `server.Listen()` unlinks the socket, a `Reachable()` probe:
if an agent answers, refuse with "an agent is already running; `jit
service restart` restarts it". Both reviews found this independently:
today a foreground run silently splits the world (launchd agent keeps
the session and every FIFO writer, new clients dial the foreground
one), and on exit it deletes the socket out from under the launchd
agent's listener, leaving a healthy process every command calls
crashed, unrecoverable except by manual restart. The same probe
serializes the double-serve-on-same-FIFO hazard.

**D6. The plist reader unescapes.** `plistProgramPath` returns the
XML-escaped string today, so for any install path containing `&`,
`agentPlistNeedsRepoint` is permanently true and `agentPlistOrphaned`
stats a nonexistent escaped path, making `ensureAgentInstalled` treat
a healthy install as orphaned and bounce it. Add `xmlUnescape`
mirroring `xmlEscaper`; test the round-trip on a metacharacter path.

**D7. Small lifecycle fixes riding along.**
- Restart's missing-plist branch uses the `running` result it already
  has instead of waiting a second 5s (`agent.go:785-793`).
- Restart's read-then-stat TOCTOU collapses to one `ReadFile`
  branching on `IsNotExist` (`:770-795`).
- `watchOwnBinary` fingerprints `selfpath.Stable(exePath)`, not raw
  `os.Executable()`, so a versioned-Caskroom exec path cannot make
  the watcher blind to an upgrade (vanished file reads as "no change
  yet" forever).
- `reloadAgentService` retries the bootout+bootstrap PAIR, not
  bootstrap alone: a genuinely failed bootout makes every bootstrap
  return "already bootstrapped", classified transient, spinning 3s
  with no chance of converging.
- `jit service ttl` (no args) clamps its display to the 8h ceiling
  the service enforces, with a parenthetical when the plist says more.
- `installAgentService` writes the plist via temp+rename (launchd or
  a concurrent reader can see a torn `os.WriteFile` today).

**Deferred, recorded here so it is not re-litigated blind:**
- `Sockets` launchd activation (a client connection as the demand) is
  the strongest fix but inverts socket ownership: launchd would
  create and hold `agent.sock`, touching permissions, peercred
  ordering, stale-socket cleanup and the foreground mode. Revisit
  only if kickstart proves insufficient in the field.
- An flock serializing concurrent first-use installs: self-healing
  today, bounded churn, not worth the lock until observed hurting.

## Phase 2: honest health vocabulary

**D8. Health surfaces consult launchd.** A `launchdJobState()` helper
behind the existing `launchctlRun` seam runs `launchctl print
gui/$UID/com.jitpass.agent` and extracts three facts: job loaded
(exit status of the print), `runs`, `last exit code`. Parsing is
confined to this one function, documented as best-effort (empty
state on any parse surprise), and never gates anything: it phrases
advice. With it:
- `jit service status` and `jit status` distinguish "loaded, never
  spawned (runs = 0): run `jit service restart`" from "loaded, last
  exit N" from "not loaded: launchd dropped the job". Today
  `Installed` means only "plist file exists" and one message covers
  every state, including a mid-restart claim that was false in the
  incident.
- `installedNotRunningAdvice` stays the single source; doctor stops
  hand-duplicating it (`doctorsections.go:558`), and a test pins
  every surface to the shared string (today: zero tests reference
  it; the drift its comment warns about already happened once).
- `jit lock` against a dead service says the truth: no service, no
  session, already locked. Today it sends the user on a restart
  errand to lock a session that does not exist (`agent.go:889-897`).
- `jit service status` handles a sick-but-answering socket the way
  `jit status` does (unreachable row + advice) instead of a raw
  command error; `notRunningHint` likewise (`:1550-1558` vs
  `status.go:422-437`).

Every string above changes user-visible output and goes through one
preview script (real `$COLUMNS` plus 50/60, ANSI kept, proposed
output only) before any code edit. The full inventory: restart's
success/timeout lines, ttl's two lines, consent's two lines,
`installedNotRunningAdvice` (three surfaces), upgrade's service
lines, migratesummary's trailer, status/doctor's new launchd-state
rows, `jit lock`'s no-service line.

## Phase 3: log and history hygiene

**D9. Resolve failures log on transition, not on cadence.** The
"skipping mount" prints (`mountmanager.go:376,387,525,531,540`) gain
the suppression their two neighbors already have: log when the error
CHANGES (appears, changes text, clears), with the existing
`errLogLast`/`errSuppressed` counter shape. `sm.lastResolveErr`
already stores the state; this is one comparison. The incident's
envelope-v4 storm (identical line every unlock for hours) recurs on
every future envelope bump until this lands.

**D10. `jit service log` renders failure as failure.**
- `agentlogview.go`'s `mountRe` learns the `skipping mount` shape so
  those lines fold like other mount rows.
- Glyph classification stops keying green on "not matching any red
  substring": resolve failures ("skipping mount", "envelope
  version", "no such file") render amber at least. Substring
  classification stays (the raw log is unstructured), but the list
  is corrected and a test drives the incident's exact lines.
- `--follow` cuts chunks at the last complete line (audit's
  `readAppended` shape) instead of tearing lines, and keeps the day
  header state across chunks.
- `noteServeError`'s `(+N similar …)` suffix folds like the reads
  suffix does.

**D11. History stays bounded while the service runs.** `hist.trim()`
runs periodically (the `rotateAgentLogPeriodically` cadence), not
only at startup; `OnServeError` durable writes get a per-source rate
limit (the ring already defends against this flood, the file does
not); `serveKey`'s pid component stops letting a re-exec-per-read
reader defeat the hour collapse (key on stable identity, keep pid in
the payload).

## Phase 4: broker hardening

**D12. Socket version skew fails closed.** The Client sends BOTH
`Disclose` and `DiscloseReason` (belt and suspenders for old
services), and requests carrying security-relevant fields gain a
`min_protocol` integer the server compares against its own; a server
too old to know a field refuses rather than silently dropping it.
Today a new CLI's `jit run --with` against an old service performs a
machine-wide reveal with NO disclosed challenge: the exact attack
`Request.Disclose`'s doc names, and the fail-open sibling of the
envelope-v4 incident (which failed closed, correctly, loudly). A
wire-compat test pins what the Client sends.

**D13. Prompt storms get the consent engine's backoff.** `OpTrust`,
`grant_create`, `grant_extend` and disclosed reveals reuse
`consent.Throttled`'s escalating backoff. The consent path gained it
because "a caller in a loop could simply outlast the user"; that
rationale applies verbatim to the op with the widest scope in the
product (OpTrust: whole-tree consent bypass) and was not carried
over. Refusals stay recorded (KindDenied), the cooldown-clearing
unlock semantics stay.

**D14. Audit truth fixes.**
- Lazy session expiry records its KindLock: `collectIfDoneLocked`
  stashes the cause, `lockIfGen` writes the event when it finds a
  lazily-collected session. Today a busy agent can show
  unlock → unlock with no lock between.
- `grant_use` collapse keys on `c.rawCommand()`, not the redacted
  command (`server.go:754-757`): redaction can map two callers onto
  one string, the misattribution `recordUse` already fixed once.
- `extendGrant` re-verifies root liveness and stops hard-coding
  `RootAlive: true` in its echo.

**D15. Small broker fixes riding along.** Grant expiry timers are
cancelled on revoke/re-extend (today they accumulate for up to 7
days); the sleep-path handler moves durable-log writes off the
kernel's power-change wait (the MEK wipe stays synchronous); `Serve`'s
ctx-watcher goroutine is joined on accept failure.

## Phase 5: mechanical split (last, pure movement)

After the fixes land (small diffs on the familiar layout), split the
two oversized files. No API changes, SPDX headers and build tags on
every new file, tests move alongside.

`internal/cli/agent.go` (1825 lines) → six files:

| File | Contents |
|---|---|
| `servicerun.go` | `agentRunCmd`, compat aliases, log rotation, `lockedWriter`, TTL validation |
| `servicelaunchd.go` | `launchctlRun` seam, reload/kickstart, install, ensure, plist template + read/unescape, wait helpers |
| `servicecmds.go` | `serviceCmd`, ttl/consent/restart, `unlockCmd`, `lockCmd`, init wiring |
| `servicestatus.go` | status command + result struct + renderers |
| `servicelog.go` | `agentLogCmd`, tail/follow |
| `agentclient.go` | `agentClient`, `notRunningHint`, `installedNotRunningAdvice`, prompt waits |

`internal/agent/server.go` (1760 lines) → `fetcher.go`,
`transport.go` (Listen/Serve/handleConn), `session.go` (the entire
mu/challengeMu discipline in one file), `events.go` (history,
recordUse family), with `server.go` keeping the struct, hooks and
dispatch. The struct's three locking regimes are currently
reconstructed by scanning 1760 lines; the split makes each regime's
home explicit.

## Test plan

Through the existing `launchctlRun` fake plus the new wait seam:
- All three restart branches, including bootstrap-succeeds-spawn-
  pended (assert kickstart issued, assert non-zero exit on timeout).
- `installAgentService` round-trip (write → `configuredAgentTTL` /
  `configuredAgentConsent`), metacharacter path, bootout-then-
  bootstrap-fails disagreement.
- `ensureAgentInstalled`: fresh, orphan-repair, reachable-orphan,
  error-not-swallowed-after-bootout.
- Self-retire: kickstart -k issued under launchd parent, fallback
  exit on launchctl error.
- `bootstrapRaceError` all three arms; pair-retry convergence.
New unit surfaces: `waitForAgentBuild` against a fake status server;
`launchdJobState` against canned `launchctl print` output; single-
source test for `installedNotRunningAdvice`; agentlogview incident-
line corpus (glyph + fold); follow-mode torn-line and day-header;
history rate-limit and mid-run trim; wire-compat pin for
Disclose/DiscloseReason/min_protocol; lazy-expiry KindLock; grant_use
raw-key collision; extend-dead-root.

## Sequencing

Each phase is a PR; 1 and 2 ship together if the wording preview
passes in one round (2's strings are 1's error paths). 3, 4, 5
follow independently. Branch off `main`; the working tree's
`dryrun-frame` work is untouched.

## Sources

Incident + launchd experiments: session of 2026-08-17 on the
production Mac (launchd-state table above). Code review: three
parallel reviews, 2026-08-17, findings folded into the decisions
above; regression history verified in git (`1e5d43e`, `660ce2c`).
