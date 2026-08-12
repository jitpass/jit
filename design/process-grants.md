# Process grants: pre-approved unattended access

**Status: proposal, being built on branch `process-grants`.**

Today every credential serve ultimately rides a session the human opened with
Touch ID, and the session dies on idle, on an 8h ceiling, on screen lock, on
sleep. That is the right default and it stays the default. The gap is the
unattended case: an AI agent working overnight, a long build, a launchd job.
The human is not at the keyboard, the screen locks, the session drops, and the
run stalls on a prompt nobody will answer.

A **process grant** moves the human decision earlier instead of removing it:
while present, the user approves with one disclosed Touch ID that a specific
**running process tree** may use the secrets of one or more named **profiles**
for a bounded **TTL**, unattended. Between creation and expiry, serves to that
tree succeed without prompts, even across screen lock. Everything else keeps
today's behavior.

    jit grant --process claude --profile jamf --profile aws-ci --for 8h

## What a grant is (and is not)

A grant is `(root process, secret set, expiry)`:

- **Root process** -- a live pid plus its fork-time stamp
  (`lineage.ProcessStartTime`), exactly the anchoring `trustRoots` and the
  run-scoped mount attachments already use. Membership is decided by
  `lineage.AncestryContainsPID`, fail-closed. The grant names a *process that
  exists right now*; it is never a name-pattern. A new process claiming the
  same name tomorrow matches nothing.
- **Secret set** -- the union of the named profiles' vault paths, resolved at
  creation time (project profile first, then global, same as `jit run`). One
  or many profiles; the grant stores concrete paths, not profile names, so a
  later profile edit does not silently widen a standing grant.
- **Expiry** -- absolute deadline, `now + --for`, hard-capped at
  `maxGrantTTL = 7d`. Checked at serve time against the record, never baked
  into key material, so revoke and expiry act immediately.

A grant is **not** a policy. It cannot match future processes, it does not
survive the agent process (v1), and it never covers secrets outside its
resolved set. Identity still never decides anything the human did not
explicitly approve: the doctrine "caller identity explains and audits, never
decides" is preserved because the *decision* is the disclosed Touch ID at
creation, bound to a kernel-vouched pid; descent-from-root afterwards is the
same fail-closed mechanism `--trust` already relies on.

## Mechanics: a scoped DEK cache, not a weaker vault

The enabling fact: the agent is a DEK-unwrapping oracle. `OpUnwrap` receives
the envelope's wrapped data key and returns the plaintext DEK; payload
decryption happens in the client. The MEK never leaves the agent, and Touch ID
is application-level (`LAContext`), not a keychain ACL.

So a grant needs no on-disk re-wrap and no new keychain item class:

1. **Creation.** The CLI resolves the profiles to vault paths and reads each
   envelope's wrapped DEK bytes and AAD-bound class (a plain file read, no
   auth). It sends `OpGrantCreate{TargetPID, profiles, entries[]{path,
   wrapped, class}}` to the agent.
2. The agent derives the process description from `TargetPID` via lineage
   (never from caller-supplied text) and runs one disclosed challenge:
   *"allow claude to use 3 secrets (jamf, aws-ci) unattended for 8h"*. The
   challenge fetches a fresh MEK, which -- unlike `discloseChallenge` today --
   is used in place to unwrap the entry DEKs (each with its class as AAD, so a
   lied-about class fails cryptographically), then wiped. Session state is
   untouched: creating a grant does not open a session.
3. The grant record holds `hash(wrapped bytes) -> DEK` in mlocked memory,
   plus metadata (id, root pid+fork-time, paths, profile names, created,
   expiry, serve count).
4. **Serve.** `OpUnwrap` checks grants before consent and before
   `ensureUnlocked`: caller descends from a live, unexpired grant root AND
   `hash(req.Data)` is in that grant's map -> return the cached DEK. No
   session needed, no consent prompt (the human approved this exact
   tool-and-secret pairing at creation), full audit record. Any miss -- wrong
   tree, expired, rotated secret, uncovered path -- falls through to today's
   path unchanged.

Scope of compromise while a grant is live: the granted secrets, for the
granted window, to the granted tree. Not the MEK, not the vault.

### The re-lock invariant, amended deliberately

Today nothing in the agent's authorization state survives `lock()`: MEK,
consent cache, trust roots, run attachments all drop. Process grants are a
new, explicitly carved-out persistence class: **grant records and their DEKs
survive re-lock by design**, because surviving the screen lock is the entire
feature. The carve-out is safe to state because a grant is strictly narrower
than the session it replaces (specific secrets, specific tree, absolute
deadline, revocable), and it is what the human approved in so many words.
Grants do NOT survive agent restart or reboot in v1 -- and cannot
meaningfully, since the root process tree dies with the boot anyway.

### End of life

A grant ends by whichever comes first; all endings wipe the cached DEKs and
emit an audit event with the cause:

- **expiry** -- lazy check at serve plus a timer so the record does not
  linger,
- **revoke** -- `jit grant revoke <id>`, no auth required (reducing access is
  always free),
- **root exit** -- fork-time re-verification fails, grant is pruned lazily on
  the next serve/list/status touch,
- **agent exit** -- memory gone.

`jit grant extend <id> --for <d>` re-runs the disclosed challenge (more time
is a new decision); shortening via `revoke` + re-create, or a later
`--shorten`, needs none.

## CLI surface

`jit grant` is a command group whose bare form creates:

    jit grant --process <name>|--pid <pid> --profile <p> [--profile <p>...] --for <dur>
    jit grant list [--format json]
    jit grant revoke <id>
    jit grant extend <id> --for <dur>

- `--process` resolves the name against the **currently running** processes
  (libproc listing, same-user only, `lineage.Process.Name()` normalization).
  Ambiguity (two claudes) is an error listing candidates with pids; `--pid`
  disambiguates. Nothing running under that name is an error, not a stored
  pattern.
- `--profile` repeats; each resolves through the normal project-then-global
  chain. `--for` accepts the `jit audit --since` duration grammar (`45m`,
  `8h`, `3d`), capped at 7d.
- Shell completion for `--process` harvests recent callers from the two audit
  trails (`audit.jsonl` Parent/LaunchedBy, `agent-history.jsonl` By/
  LaunchedBy, last 24h), deduped, annotated running/not-running, rendered as
  cobra `name\tdescription` pairs. Read-only, no agent RPC, no prompt, no
  state mutation, NoFileComp.
- Output follows the house style: `[Grants] N` header, `●` live rows with
  expiry countdown and serve counts, `!` nudge plus a `→ jit grant revoke`
  hint for a grant that is long-lived and unused. A preview script exists in
  the session scratchpad and the rendering will be re-previewed before the
  final polish.

## Protocol and audit

New ops `grant_create`, `grant_list`, `grant_revoke`, `grant_extend` join the
existing one-request-per-connection protocol; `Response` gains a
`Grants []GrantStatus`. All four verify the peer as every op does; `create`
and `extend` additionally require the disclosed challenge; a nil caller is
rejected on `create` (a grant must be traceable to a requesting human
context).

Audit trail (both files already merged by `jit audit`):

- creation and extension -> `KindApproved` with the exact prompt wording as
  `Cause` (renders today as `kind=grant status=approved`),
- serves under a grant -> aggregated `KindUse` with op `grant-use`, labels
  carrying the vault paths, collapse-per-caller like session uses,
- endings -> new `KindGrantEnd` with `Cause` = `expired` | `revoked` |
  `process-exit`, rendered by `jit audit` and aliased under `--kind grant`.

## Limits, stated plainly

- **Env injection is still up-front.** A `jit run` that already injected env
  vars gave the tree those values with no further serves; grants change
  nothing there. Grants shine for pull-at-use paths: credential helpers,
  capture shims, repeated `jit run` invocations by an agent.
- **FIFO mounts are out of scope in v1.** The best-effort reader-scan path
  keeps its own consent gating; extending grants to mounts is a later,
  separate decision.
- **Rotation invalidates silently but safely.** Rotating a covered secret
  changes its wrapped DEK; the grant simply stops matching and the serve
  falls back to prompting.
- **Agent restart drops grants.** `jit grant list` after a restart is empty;
  the audit trail still shows what existed. Acceptable for v1; a persisted
  (metadata-only) ledger is a possible v2, but the DEKs themselves should
  never touch disk.
- **v2 candidates, not now:** binding by code-signing identity (survives
  restarts, murky for interpreter-run tools), grants offered directly from
  the consent prompt ("allow once / 1h / 8h"), `jit status` surfacing.
