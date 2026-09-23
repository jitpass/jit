# Standing grants: a grant that is its own key

**Status: built 2026-09-23, not yet released.** Agent
(`internal/agent/standing.go`, `internal/keychainwrap/grantkey.go`), CLI
(`jit grant --until-revoked`), and the app (jit-app: `GrantsView`,
`GrantSheetView`, `GrantSheetLists`, `ProfileDiscovery`, `GrantDraft`;
mockup kept at `docs/design/mockups/Grants-redesign.html`). The app needs
an agent from the jit release that carries this; until `jit.version` is
bumped, the bundled agent refuses the new create for naming no profiles.
Where the build departs from the drawing, and why, is under "App" below.
Supersedes the "Agent restart
drops grants" and "DEKs should never touch disk" limits in
`process-grants.md`, and states what the Secure Enclave move will and will
not change. Read `process-grants.md` first; everything there that is not
contradicted here still holds.

The ask, in the user's words: *a grant that does not require Touch ID as
long as the grant exists in jit.* Not a deadline, not a schedule. A
standing decision, revocable, that survives screen lock, the idle timer,
a service restart and a reboot.

    jit grant --process claude --profile mcp-caido --profile mcp-urlscan --until-revoked

## The facts this rests on (verified in code, 2026-09-23)

Every design choice below follows from one of these. If one of them
changes, revisit the choice that cites it.

1. **Touch ID is consent, not a lock.** The MEK is a plain keychain item
   (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no `SecAccessControl`;
   `internal/keychainwrap/keychain.m:107`). The Touch ID prompt is
   `LAContext.evaluatePolicy` run by jit's own code before the fetch, and
   the package says so verbatim at `keychainwrap.go:19`: *not
   cryptographically enforced*. A process running as this user can read
   the item without any prompt. This is the shipped interim until the
   Secure Enclave path exists (see the last section).
2. **Two gates decide an ordinary unwrap.** The session (a live MEK
   serves with no prompt; `touchSession`), and per-process consent, which
   only fires for the credential classes in
   `internal/consent/policy.go` — never for `mcp` or `dotenv`, which is
   what every profile on the author's own Mac resolves to. For those
   secrets the only Touch ID anyone ever sees is the vault being locked.
3. **A grant answers before both gates** (the `OpUnwrap` case in
   `internal/agent/server.go`, which calls `grantUnwrap` first),
   from plaintext DEKs it unwrapped at creation and holds in mlocked
   memory. That is why today's grant needs no session, survives lock, has
   a hard deadline, and dies with the process: the deadline is the
   lifetime of key material in RAM.
4. **The envelope already has a recipients map**
   (`internal/vault/envelope.go:66`), and `envelopeAAD` does not bind it,
   so adding a recipient is a plain JSON rewrite. But `wrappedDEKFor`'s
   single-recipient fallback (an envelope keyed by a stale hostname still
   opens because it has exactly one recipient) breaks the moment a second
   recipient is added. Any design that writes recipients must re-key that
   case first.
5. **`lineage.Process` exposes `ExecPath`** (`internal/lineage/caller.go:31`),
   so an anchor can be the session root's executable path, which survives
   a reboot, where a pid does not.
6. **The Secure Enclave is one packaging step away, not a re-architecture.**
   Persisting an SE key needs a provisioning profile in an `.app` bundle
   (`spike/secure-enclave/FINDINGS.md`, 2026-07-11). The running agent is
   already `JitPass.app/Contents/MacOS/jit`, and the launchd plist already
   points there. Developer ID signing (2026-07-30) and notarization
   (v0.80.0) are done. What is missing: the agent as its own signed
   helper bundle carrying `embedded.provisionprofile` and the keychain
   entitlement. `JitPass.app` carries neither today (checked:
   `codesign -d --entitlements` is empty, no `embedded.provisionprofile`).

## Why "a grant is a key" and not "a grant is a rule"

A rule ("claude under iTerm2 may use mcp-caido") cannot decrypt anything.
When the vault is locked the MEK is wiped, and a rule has nothing to
unwrap with. There are exactly two sources of a key at that moment: key
material already in memory (today's grant, hence its deadline), or the
MEK, which needs a Touch ID to come back. A rule alone would work only
while the vault happens to be unlocked, which is not what was asked for.

So the grant holds a **key of its own**. At creation, under the one Touch
ID, the covered DEKs are re-wrapped under a fresh **grant key**. The grant
key lives in the keychain as its own item. Serving needs the grant key
and nothing else: not the MEK, not the session, not a prompt. Given fact
1, this adds no exposure the vault does not already carry: the grant key
is protected exactly as the MEK is, and it opens strictly fewer secrets.

## What a standing grant is

`(anchor, program, secret set, grant key)`. No expiry.

- **Anchor** — the session root's executable path
  (`/Applications/iTerm.app/Contents/MacOS/iTerm2`), plus its display
  name for the prompt and the list. Not a pid: a pid does not survive a
  reboot, and the whole point is to survive one. Verified at every serve
  by walking the caller's ancestry to its session root and comparing
  `ExecPath`.
- **Program** — the display name that narrows the tree
  (`lineage.AncestryNamedWithin`), exactly as tree-scoped grants do today.
  The program's `ExecPath` at creation is recorded and shown, never
  gated: Claude Code's path carries its version and changes on upgrade
  (`caller.go:43`).
- **Secret set** — resolved at creation through `OnResolveGrant`
  (project profiles first, then global; `jit run`'s order). Concrete
  paths, so a later profile edit never widens a standing grant.
- **Grant key** — 32 random bytes, generated at creation, stored as
  keychain item service `com.jitpass.grant.key`, account `<grant id>`,
  same accessibility as the MEK. Cached in mlocked memory while the agent
  runs; wiped on revoke.

### Anchoring without a pid, stated plainly

Today's anchor is a kernel-vouched pid plus fork time. A standing grant
gives that up for an executable path plus a name. What is lost: a
same-named program, started under the same app, by something else inside
your own login session, is covered. What is kept: nothing outside that
app's process tree is ever covered, and the tree is still verified by the
kernel on every serve. The doctrine holds as before: the *decision* is
the disclosed Touch ID at creation; ancestry afterwards only narrows.

Two further weaknesses of a path anchor, which the paragraph above does
not cover and a reviewer should not have to rediscover:

- **Nothing verifies the code at that path.** A pid anchor cannot be
  forged after creation; a path anchor is re-resolved on every serve, so
  whoever can WRITE to `anchorPath` substitutes the binary and keeps the
  grant. A user-writable `/Applications` bundle, `~/Applications`, or a
  Homebrew-installed terminal under `/opt/homebrew` all qualify. There is
  no code-signing or inode check. This is the strongest argument for the
  Secure Enclave move, where the OS holds the key rather than jit's own
  discipline, and for a later code-requirement check on the anchor.
- **Neither side of the comparison is canonicalized.** Symlinks and case
  are compared as written, so an anchor reached by a different spelling of
  the same file does not match. That direction fails closed, which is the
  safe one, but it means an anchor can silently stop working.

A later `--exec <path>` can pin the program for scripts with stable
paths. Not in v1.

## Mechanics

### Create

1. The CLI or app sends `grant_create{ standing: true, grant_name,
   target_pid (the session root), grant_profile_roots }`. No
   `ttl_seconds`; sending both is an error. (`grant_profile_roots` is the
   name-and-folder pair described under **App** below; it replaced the
   `grant_profiles` + one `project_root` pair, which cannot express two
   profiles beside two different projects.)
2. The agent resolves the profiles (`OnResolveGrant`), derives the anchor
   from `target_pid` via lineage, and runs the disclosed challenge:
   *"Let claude under iTerm2 use mcp-caido and mcp-urlscan until you
   revoke it."* The wording is the app's sentence, word for word.
3. The challenge's MEK unwraps each DEK with its class as AAD (as today).
   A fresh grant key is generated. Each DEK is sealed under the grant key
   with the same class AAD (`seal(gk, dek, class)`, the primitive in
   `keychainwrap/crypto.go`). The MEK and every plaintext DEK are wiped.
4. The grant key is written to the keychain. The record is appended to
   the ledger. `KindApproved` is recorded with the prompt wording as
   `Cause`.

### The ledger

`~/Library/Application Support/jitpass/grants.json`, mode 0600, written
atomically. One entry per standing grant:

    version: 1
    grants[]:
      id, created_unix
      anchor { exec_path, name }
      program { name, exec_path_at_creation }
      profiles[] { name, root }
      secrets[] { path, class, device_wrapped_sha256, grant_wrapped (hex), wrap: "aead-v1" }
      serves, last_serve_unix

`version` is checked on load: a file written by a NEWER jit is refused and
then never written back over, so a downgrade cannot silently truncate a
grant it does not understand. Within a file this build can read, a secret
whose `wrap` it does not recognise is **skipped**, so the grant comes back
covering fewer secrets than were approved — the list's rotation reporting
is what makes that visible rather than silent.

Two operational facts that belong here rather than in a reader's surprise.
The ledger is rewritten on **every serve**, because `serves` and
`last_serve_unix` live in it: one credential read costs a JSON marshal, a
temp-file write and a rename. That is cheap beside the AEAD open it
accompanies, and it is why a serve's bookkeeping failure is deliberately
ignored rather than failing the serve. And the whole file is rewritten each
time, not appended to, so a grant's entry cannot be partially updated.

Never a DEK, never the grant key. The ledger and the keychain item are
the same trust tier as the vault's envelopes and the MEK: wrapped
material on disk, its key in the keychain. `process-grants.md`'s rule
"the DEKs themselves should never touch disk" is kept; what touches disk
is a wrap under a key that is not on disk.

`device_wrapped_sha256` is the hash the serve path already keys on: the
client sends the envelope's device-recipient wrapped bytes on every
unwrap, and a standing grant matches on their hash exactly as a timed one
does. No vault file is touched by creating a grant.

### Serve

`OpUnwrap`, in the position it already holds (before consent, before the
session):

1. Find the caller's session root; compare its `ExecPath` to each
   standing grant's anchor. For a match, `AncestryNamedWithin(caller,
   root, program.name)`.
2. `sha256(req.Data)` must be in that grant's secrets. Miss falls through
   to the ordinary path unchanged, including a rotated secret.
3. Fetch the grant key (keychain on first use, then the mlocked cache),
   `open(gk, grant_wrapped, class)`, return the DEK. Record `grant_use`.

No session is opened, no MEK is fetched, nothing prompts.

### Restart and reboot

At service start the ledger is loaded. Nothing is re-armed and no unlock
is needed: the anchor is found per serve, and the key is fetched on
demand. `jit grant list` after a reboot shows the same grants it showed
before.

### Revoke

Delete the keychain item, wipe the cached key, remove the ledger entry,
record `KindGrantEnd` with cause `revoked`. The ledger's wrapped copies
are garbage without the key. As today, revoke needs no authentication.

### Rotation, and anything else that uncovers a secret

A rotated secret has new wrapped bytes; its hash misses; the serve falls
through to a prompt. A secret DELETED from the vault reports identically,
because the check is "does the vault still hold what this grant covers",
and it cannot distinguish the two. The wire field is named `rotated` for
the common case; the surfaces say "no longer covered", which is true of
both. This is correct and is the existing behaviour, but
it must be visible: `jit grant list` and the app compare each ledger hash
with the envelope's current wrapped bytes (a plain file read, no prompt)
and mark the secret *rotated, re-approve*. Re-approval is a new create;
a later `jit grant refresh <id>` can re-wrap only the rotated ones under
one Touch ID.

### Timed grants keep their shape

Every grant with a deadline, `--pid` and `--process` alike, stays exactly
as `process-grants.md` describes: DEKs in memory, 7d cap, anchored to a
kernel-vouched pid plus fork time, dies with the service. The first draft
of this design moved timed `--process` grants onto the ledger too, and the
build deliberately did not: a ledger grant anchors by executable path,
which is strictly weaker than the pid-and-fork-time anchor a timed tree
grant has today, and a timed grant gains nothing from surviving a restart
that a fresh `jit grant` would not give it. Two mechanisms, one per
guarantee: memory and a pid for "until a deadline", a key and a path for
"until revoked". `grant_create` refuses `standing` with a TTL, so no grant
is ever half of each.

### What the serve check actually walks

`lineage.AncestryNamedUnderPath(caller, anchorPath, name)`: up the
caller's parent chain, the name must be seen at or below a process whose
`ExecPath` is the anchor, and the walk never reaches launchd. The anchor
may therefore be any ancestor the human chose at creation (the app passes
the session root; `jit grant` from a terminal passes its own session
root), not only the topmost one; creation still verifies the anchor is the
caller's ancestor or an explicit session root, as for tree grants.

### The prompt within its budget

The disclosed prompt is the sheet's sentence, but macOS gives it a hard
length budget (`maxReasonLen`, 90 runes), and a tree grant's profile list
is the part that yields: "let claude under iTerm2 use 2 secrets
(mcp-caido, mcp-…) until you revoke it". The scope clause is never the
half that goes. The sheet shows the full sentence; the prompt shows it
within the budget.

## Protocol

- `Request`: `standing bool` on `grant_create`, exclusive with
  `ttl_seconds`; and `grant_profile_roots []GrantProfile` ({name, root}),
  which replaces the `grant_profiles` + single `project_root` pair.
- `GrantStatus`: `standing bool`, `anchor_path string`, `profile_roots
  []GrantProfile`, `rotated []string` (paths the vault no longer holds as
  granted), and `expires_unix` carrying a far-future **compatibility**
  instant, 2099-12-31.
- That compat instant is the one piece of the wire that is not literally
  true, and it exists because of a client that cannot be changed. A jit
  older than this feature has no `standing` field to read, so it renders
  whatever `expires_unix` holds: zero came out as the Unix epoch and
  printed a live grant as *"expires Thu 02:00 (0m left)"* — never-expires
  reading as long-expired, the worst direction for that error. A
  far-future instant is the standard way to tell a field that insists on a
  deadline that there is none; the old client then shows tens of thousands
  of days remaining, which is true. Every current reader MUST branch on
  `standing` and ignore it. One thing it cannot fix: the old renderer
  drops the DATE past tomorrow and prints a bare weekday, so old `jit
  status` still shows a meaningless clock with no countdown beside it.
- Ops unchanged: `grant_create`, `grant_list`, `grant_revoke`,
  `grant_extend` (refused on a standing grant: there is nothing to
  extend).

## CLI

    jit grant --process <name> --profile <p>... --until-revoked
    jit grant --process <name> --profile <p>... --for <dur>      # unchanged
    jit grant list                                             # "until revoked", and what a rotation stopped
    jit grant revoke <id>                                      # unchanged

`--until-revoked` is an explicit flag. Omitting `--for` never mints a
standing grant; a typo must fail loudly, as `--for 30d` does today.

## App

The sheet and the Grants window are drawn at
<https://claude.ai/artifact/Y2hFd3C2rVXJeFgjDJxxCA>. What this design
changes there:

- **When** gains *Until revoked* beside the durations, and it is the
  default for the tree cover. The sentence reads "… until you revoke it."
- **No folder is ever chosen.** The sheet lists every profile on the Mac,
  filterable, and prints each one's folder under its name only so two
  similar profiles can be told apart. This fixes the greyed-out button:
  the sheet listed `~/.jit/profiles` only, and every profile on the
  author's Mac is kept beside a project.

  **Discovery** unions three sources, cheapest first, then dedupes and
  sorts by profile name: every `profile_path`'s project root in
  `mounts.yaml` (the registry already stores absolute manifest paths);
  the working directories of the processes the sheet already lists, and
  each one's ancestors up to the home directory, where a `.jit/profiles`
  exists; and `profile.GlobalRoot()`. "Add a Folder…" covers anything
  missed and is never the first step. On the author's Mac the three
  sources yield all ten profiles without a click.

  A folder is **not** a scope and must never be labelled or worded as
  one. The grant resolves names to concrete vault paths at creation and
  matches on the process tree and the secret's hash at serve time, so a
  folder reaches nothing after creation: a grant made from profiles in
  `~/Security-Ops` serves that program in any directory. Two drafts got
  this wrong, and both failed on their first reader. The first called the
  row "Project" and wrote "Let claude in ~/Security-Ops use …", which
  read as a scope and was false. The second kept a folder popup labelled
  "from", which answered a question nobody had asked: *why am I choosing
  where the profile is?* The sentence names no folder at all.

- **`grant_create` gains a folder per profile.** It carries
  `grant_profiles []string` plus one `project_root` today, so a
  machine-wide list cannot express two profiles from different folders in
  one grant. Replace both with a repeated `{name, root}`, keeping the
  rule that matters: the agent resolves the names itself, so nothing can
  name one profile on the prompt and grant another. This is the only wire
  change the app's design forces; everything else is client-side.
- Grants window eyebrows, in the order `Format.grantTier` ranks them:
  *Needs you* (amber) when a covered secret stopped being served, *Serving*
  (green) when it served in the last minute, *Ending* (amber) for any timed
  grant whose anchor is gone — a pid whose process exited, or a tree grant
  whose terminal quit — *Standing* (grey) for a grant with no deadline, and
  *Active* (grey) for a timed one. **Needs you outranks Serving**: a grant
  actively serving its healthy secrets still shows Needs you while one of
  them is uncovered, because that is the state only the human can clear.
  The rotated secrets are their own rows under the grant's, each naming the
  secret; the card above carries the count and *Re-approve…*.

- **The sheet checks the vault before it lets you tick a profile**, which
  the mockup never drew. The service refuses a whole create if any one
  named secret is missing from the vault, so a profile naming one would
  spend a Touch ID only to fail. `reloadGrantSheet` therefore reads
  `jit vault list` (prompt-free, paths only) and dims any profile with a
  missing path, saying how many. This is a client-side gate on what can be
  granted, so it is recorded here rather than left to be discovered: its
  failure mode is a profile the sheet will not let you pick, and the reason
  is on the row. It is a convenience over the service's own refusal, never
  a substitute — the service still re-resolves and still refuses.

- **The app's Audit window learned to name grant events**, which is a
  change to a surface this document otherwise describes only on the agent
  side. An approval carrying `grant_create` reads "grant approved, asked by
  JitPass" with the approved sentence beneath it; a serve reads "… read …
  via grant"; an ending reads the agent's own cause. Before this they were
  a generic "approved JitPass" and "used", so a grant made seconds earlier
  was invisible in the window it should be most visible in.

- **`jit status`'s grants row** now ends "until revoked" when no live grant
  has a deadline, in place of "next expires <clock>". A standing grant is
  skipped when computing the soonest expiry, or it would always win.
- The schedule (days and hours) drawn in the mockup is **deferred**. A
  standing grant answers the ask without it; if it returns it is one
  predicate beside the anchor check, and the mockup already shows it.

**Where the built app departs from the mockup, and why** (2026-09-23):

- A timed grant that is not serving right now shows the eyebrow *Active*
  (grey), which the mockup never drew: it drew only standing, serving and
  ending cards. *Standing* now names the no-deadline kind, so a timed
  grant could not borrow it, and the row's second line carries the
  deadline ("ends today, 23:55").
- A rotated secret's row says "Not served since it changed" without the
  time it changed. The agent reports which secrets rotated
  (`GrantStatus.Rotated`) and not when; the envelope's `UpdatedUnix` would
  need one more hook, so the time waits for a reason to add it.
- *Re-approve…* opens the sheet filled with the grant as it was and, once
  the new grant exists, revokes the old one: one Touch ID, every secret
  re-wrapped, the ledger's stale copies gone. The mockup's caption said
  "re-wraps only that secret"; that is the `jit grant refresh` this
  document leaves for later, and a new grant is what it says re-approval
  is. Ordering matters: the old grant is revoked only after the new one
  lands, so a refused prompt leaves it serving what it still can.
- The sheet opens with its blanks empty, as drawn, rather than guessing
  "claude" as the old sheet did. A re-approval is the one prefilled case.

## Audit

- Creation: `KindApproved`, `Cause` = the prompt wording.
- Serves: `grant_use`, unchanged.
- Revoke: `KindGrantEnd`, cause `revoked`. A standing grant has no other
  ending: it does not expire, its anchor app quitting does not end it, and
  a service stop ends only the TIMED grants beside it (`endTimedGrants`,
  which this document's sibling now records — see `process-grants.md`'s
  End of life).
- Ledger load at start: one `agent.log` line naming the count. Not an
  audit event; nothing was decided.

## What it is worth today, honestly

Equal to the vault's own protection and narrower in scope: the grant key
is a plain keychain item exactly as the MEK is, and it opens only the
named secrets, only for the named tree, kernel-verified, every serve
audited. It does not weaken what exists. It does not strengthen it until
the enclave.

## Build order

1. Agent: ledger, grant-key keychain item behind `vault.KeyWrapper` (a
   wrapper per grant id; see the next section for why), create, serve,
   revoke, rotation marking. Tests, each with its negative control:
   create then restart the server then serve with no session and no
   prompt; revoke then serve prompts; rotate then serve prompts and list
   marks it; a same-named program under a different app is refused.
2. CLI: `--until-revoked`, list rendering, `extend` refusal.
3. App: Project row, *Until revoked*, eyebrows, per the mockup.
4. `process-grants.md`: strike the two superseded limits.

## For the Secure Enclave move: what we learned, so it is not relearned

Written 2026-09-23 from the spikes, the shipped `keychainwrap`, and this
design. Keep it current.

- **Both keys move, one flag apart.** The MEK becomes an enclave key
  created *with* the biometry access-control flag: the OS refuses to use
  it without a fingerprint. The grant key becomes an enclave key created
  *without* that flag, usable by the signed agent alone and never asking.
  If only the MEK moved, the grant key would become the weakest item in
  the vault.
- **Build the grant key behind `vault.KeyWrapper` from day one.** An
  enclave key is a handle you ask to perform an operation, never bytes
  you hold. A grant built as "fetch 32 bytes, call `open`" is a rewrite
  on the enclave; a grant built as a `KeyWrapper` keyed by grant id is a
  configuration change, the same swap `keychainwrap`'s own comment
  promises for the MEK.
- **Version the wrap in the ledger now.** `wrap: "aead-v1"` today;
  `"se-p256-v1"` later (P-256 ECDH → HKDF → AEAD, per `TECH_STACK.md`
  §3). A ledger entry says which it is, so both can coexist during a
  migration and a re-wrap is a per-grant Touch ID, not a flag day.
- **Revoke gets stronger, not different.** Deleting an enclave key makes
  the ledger's wrapped copies unrecoverable on every machine, forever.
  Today a deleted keychain item is merely gone.
- **Grants become device-bound.** An enclave key cannot leave the Mac.
  That is the right meaning for something scoped to one process tree on
  one machine, and it is what the anchor already assumes.
- **The precondition is packaging.** The agent needs to be its own signed
  bundle with `embedded.provisionprofile` authorizing
  `keychain-access-groups`. It already runs from
  `JitPass.app/Contents/MacOS/jit` via `~/Library/LaunchAgents/com.jitpass.agent.plist`;
  the bundle carries no profile and no keychain entitlement yet. Apple's
  rule: a profile lives in a bundle, never in a bare Mach-O
  (`spike/secure-enclave/FINDINGS.md`, 2026-07-11 update).
- **Nothing in this design changes on the move.** The ledger, the anchor,
  the serve position, revoke, rotation, audit, the CLI and the app are
  the same. Only what the two keys are, and who enforces them.
- **If envelope recipients are ever written** (RFC §5.2 sharing, or a
  vault-visible "also openable by grant g-7f3a"): the AAD does not bind
  them (fact 4), but `wrappedDEKFor`'s single-recipient fallback must be
  replaced by an explicit re-key of stale-hostname envelopes to the
  current device id before any second recipient is added, or those
  envelopes stop opening.
