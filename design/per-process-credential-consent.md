# Per-process credential consent

**Status: SHIPPED.** `internal/consent` is the engine (`Engine`, `Prompter`,
`Decision`, `Scope`, plus `policy.go`'s gated-class set); `internal/agent`'s
`gateConsent` and `ConsentReaders` are the two call sites; `jit run --trust`
exists. `docs/security/architecture.md` documents the shipped behaviour and is
accurate -- prefer it for how the feature works today, and read this file for
the threat model it was built against.

This said "proposal, unbuilt ... so it can be picked up later" until
2026-08-06, long after it was built. Three sections below described the design
as proposed rather than as delivered, and the notes on each say where the
shipped answer differs -- an implementer following the original text would have
built the wrong thing or rebuilt something that exists.

Today a `jit run --with <name>` (or a `--grant` shim) reveals a machine-global
credential to the **whole process tree** of the run, after one disclosed Touch
ID at grant time. This proposal narrows that: when a *specific* process inside a
run reaches for a mediated credential, jit identifies that process (and who
launched it) and asks you to allow or deny **that** access, instead of trusting
the entire tree by default. Think macOS TCC or Little Snitch, but for
credentials.

## What we actually worry about

jit's baseline already defeats the classic threat. Secrets at rest are encrypted
in the vault behind Touch ID; on disk every file is a decoy, so anything that
scans your home directory for plaintext (`~/.aws/credentials`, `.env`, `.npmrc`)
gets fakes. An app you did not launch gets decoys and would still need an
unlocked session and to route through jit.

The residual worry is different, and it is the modern one: **untrusted code
executing inside a run you launched and blessed.** When you run `npm install`,
`npm run dev`, `terraform apply`, or an AI agent, you are not running only your
own code. You are running:

- hundreds of transitive dependencies you never read,
- package lifecycle scripts (`postinstall`) that execute arbitrary code,
- an AI agent autonomously running commands with your permissions,
- build plugins, git hooks, and other subprocesses.

"I ran it, so I trust it" conflates *"I intended this task"* with *"I vetted
every line of third-party code in it."* Supply-chain attacks (a poisoned
dependency, a typosquat, a compromised `postinstall`) live in that gap. Because
`jit run` currently serves the run's whole tree, one malicious member of that
tree sees whatever the run was granted.

Per-process consent addresses exactly this: the grant stops being all-or-nothing
for the tree and becomes a decision about the individual process that asks.

## What already exists to build on

The hard plumbing is present:

- `internal/agent/peercred.go` identifies a socket peer's PID via Darwin
  `LOCAL_PEERPID`, and verifies same-user via `LOCAL_PEERCRED`.
- `internal/agent/caller.go` plus `internal/lineage` resolve the caller and its
  provenance (who launched it), used today to record and verify callers.
- `GrantGlobalForPID` / `RunForPID` already scope a grant to a PID's tree.

So identifying "which process is asking, and who launched it" is not new work; it
is a policy layer over machinery jit already relies on.

## The mechanism, and where it works

Feasibility splits by **how the credential is delivered**, because consent
requires knowing the caller at the moment of access.

### Works: hook-delivered credentials (has a socket, has a caller PID)

When a process fetches through a hook it runs `jit …` and connects to the agent
socket, so jit knows the caller PID and can walk its lineage. This covers:

- `sops` via the `SOPS_AGE_KEY_CMD` broker (see the sops wiring),
- `aws` via `credential_process`,
- `git` and `docker` credential helpers,
- `kubectl` exec plugin.

For these, on first access jit can pause and prompt, naming the process and its
launcher: *"`node .../node_modules/foo/postinstall.js` (launched by your `npm
install`) wants your `gcp` credential: allow / deny / always for this run?"*

### FIFO file mounts (no socket, no caller PID) -- SOLVED DIFFERENTLY

> **Shipped:** mounts ARE gated, without the redesign this section calls for.
> `internal/consent` added a `Strength` axis (`Hard` / `BestEffort`) that this
> proposal did not anticipate: the mount serve path identifies the reader
> best-effort via libproc and gates on that, and Strength never decides an
> allow or a deny -- a weak identity is not grounds to refuse -- it only
> partitions the decision cache. No FUSE layer was needed. See
> `docs/security/architecture.md` and `internal/consent/consent.go`.

`gcp`, `npm`, and `netrc` are served through a named pipe. A plain file read
carries no caller identity (`caller.go` notes: "no socket, therefore no peer
pid"), which is exactly why those are whole-tree grants today. Per-process
consent for them needs a delivery redesign (a FUSE layer that sees the reader,
or moving the credential onto a hook where the tool supports one). This is a
further argument for preferring hooks over file mounts, and a concrete payoff of
giving sops its hook.

### Out of scope by construction: environment injection

Secrets injected into the environment (`jit run -- npm run dev` with a project
`.env`) are handed to the whole tree *before* any child runs. jit cannot
retroactively un-inject them per child, so a `postinstall` reading `process.env`
gets them with no prompt. Per-process consent is a **pull-at-use** feature; it
does not cover up-front env injection. State this plainly so the protection is
not over-sold.

## The `--trust` bypass

Prompting per process is the safe default for a run whose tree you do not fully
trust. When you *do* trust the whole tree, opt out:

    jit run --trust -- <cmd>           # grant the whole tree, no per-process prompts

> **Shipped as a BOOLEAN**, not a flag taking a credential name: `--trust`
> pre-authorizes the run's whole process tree for any credential. See
> `internal/cli/run.go`.

This is essentially today's grant behavior, made explicit. The existing
`jit wrap add <tool> --grant <name>` shim is the durable, per-tool form of the
same trust decision ("gcloud runs are always trusted for gcp").

## Design questions -- RESOLVED IN CODE

> Both of the first two were answered and are load-bearing; they are kept here
> for the reasoning, not as open work. Prompt fatigue: `Request.key` keys the
> cache on credential plus the caller's launcher, with a single-flight so
> concurrent first accesses produce one prompt, and a refusal earns a bounded
> backoff (`Throttled`) rather than a cached deny. Caller identity: the
> launcher's executable path, with the `Strength` axis above for how much it
> can be trusted. `docs/security/architecture.md` documents both.

- **Prompt fatigue.** SDKs and tools call repeatedly. A prompt per call is
  unusable. Cache a decision at least for the run, keyed by (caller identity,
  credential). Consider "always for this tool" that writes the `--grant` shim.
- **Caller identity granularity.** jit knows the process path, argv, and parent
  chain, not a canonical "package name." Decide what to display and what to key
  the remembered decision on (exact executable path is stable; argv less so).
- **Lineage after exec.** `LOCAL_PEERPID` is captured at connect time and a
  process can `exec` afterward; confirm the identity shown matches the code that
  actually reads the secret.
- **Denial semantics.** On deny, the tool should get the same local parse error
  or decoy it gets when a grant is absent, and fail fast, not hang.
- **Headless / CI.** With no one to answer a prompt, the access must fail
  closed (or require `--trust`), never block forever.
- **Audit.** Every allow and deny should land in `jit audit` with the caller and
  credential, so the prompt history is reviewable after the fact.

## Relationship to existing features

- Keeps the `--with` intent gate intact: a repo's config still can never reach a
  global credential. This narrows *what inside a granted run* can use it, it does
  not loosen *who can grant*.
- Builds on the run-scoped reveal grant and the disclosed-challenge model, adding
  per-caller granularity rather than replacing them.
- Motivates hook delivery generally, and specifically rewards the sops
  `SOPS_AGE_KEY_CMD` hook by moving sops from the un-promptable FIFO onto the
  promptable socket path.
