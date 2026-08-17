# 1Password adapter: reference secrets resolved through `op`

**Status: draft — issue #60 (maelp): "Could there be an adapter for
1Password storage, possibly through `op` cli?"**

A 1Password user's secrets already have a home: synced, shared with a
team, rotated in the 1Password app. Today jit asks that user to copy
values into its own vault, which creates a second source of truth that
starts drifting the moment a teammate rotates a key. The adapter removes
the copy: a vault entry may hold a **reference** to a 1Password item
instead of a literal value, and jit resolves it at delivery time by
running `op read`. 1Password stays the system of record; jit stays the
just-in-time delivery and policy layer — the parts 1Password does not
have: decoy FIFO mounts, per-process consent, process-tree grants,
native credential-helper protocols, scan/migrate, one audit surface.

That framing decides the scope: **read-only, value-level**. jit never
writes to 1Password, and there is no "storage backend" abstraction —
a reference is just a different kind of payload inside the existing
envelope, resolved at the one place every consumer already funnels
through (`Vault.Get`). Every injection tier inherits 1Password support
at once, with no per-tier work.

## What `op` gives us (verified against the CLI docs, 2026-08)

- **Secret references**: `op://<vault>/<item>[/<section>]/<field>`,
  1Password's own URI scheme, copyable from the desktop app and stable
  across value rotation. Query parameters cover OTPs
  (`?attribute=otp`) and SSH key formats (`?ssh-format=openssh`).
- **`op read -n <ref>`** prints the exact field bytes to stdout; `-n`
  suppresses the trailing newline op otherwise appends, which matters
  for byte-exact injection.
- **Desktop-app integration**: `op` authenticates through the
  1Password app (Touch ID / Apple Watch / device password) over XPC
  with mutual code-signature verification, and logs CLI activity in
  the app. Authorization is per account, per **terminal session**
  (the macOS session credential is the tty plus its start time): a
  10-minute inactivity expiry that refreshes on each use, a 12-hour
  hard cap, and **every authorization is revoked when the app
  locks**. The prompt names the account and the process being
  authorized. An encrypted in-memory cache daemon (default on for
  UNIX) cuts API calls between commands. `OP_BIOMETRIC_UNLOCK_ENABLED`
  and `OP_ACCOUNT` tune it from the environment; account selection
  precedence is `--account`, then `OP_ACCOUNT`, then the most recent
  `op signin`.
- **Enumeration hands us everything**: `op item get --format json`
  returns each field with its concealed value AND a ready-made
  `reference` key (name form); vault, item, and field ids sit in the
  same output, so ID-form references are assembled from one pass.
- **Service accounts** exist for headless use (vault-scoped token in
  `OP_SERVICE_ACCOUNT_TOKEN`). Deliberately out of scope for v1: the
  token is itself a credential jit would then need to store, and the
  attended desktop-app path is the one the issue is about.

Note the overlap: `op run` / `op inject` / shell plugins already do
Tier-1-style env injection. The adapter's value is everything op
cannot do, listed above — which is also why resolution belongs at the
vault layer and not as a wrapper around `op run`.

## The shape: a reference is an encrypted payload, not a new store

A linked secret is a normal envelope whose decrypted payload is the
`op://` URI, plus an authoritative marker saying "resolve me, don't
serve me". Two properties fall out, both deliberate:

- **The reference is encrypted and consent-gated like any secret.**
  An `op://` URI names your 1Password vault, item, and field — your
  credential map. More importantly, gating its DEK unwrap is what
  keeps jit's per-process consent, class-AAD policy, and process
  grants meaningful for linked secrets: the agent's decision point is
  unchanged, it just guards a pointer instead of the bytes.
- **The marker is AAD-bound, never sniffed.** Dispatching on "payload
  happens to start with `op://`" would silently morph a literal value
  into a network fetch. Instead the envelope grows an explicit field,
  bound into the AAD so it cannot be flipped on disk: marking a
  literal secret as a reference (or the reverse) fails decryption.

### Envelope v4

```
Storage string `json:"storage,omitempty"`   // "" = literal value
                                            // "op-ref" = payload is an op:// URI
```

- `envelopeVersion` bumps to 4. v4's AAD string appends `storage`
  after `origin`; Get reconstructs per stored version exactly as the
  v2/v3 branch does today. v1–v3 files stay readable forever,
  unchanged.
- Rekey (`rewrapFile`) already round-trips the whole envelope struct
  and never re-seals the payload, so `storage` survives a rekey by
  construction — but a rekey-a-reference test pins that, since a
  dropped field here would silently turn a pointer into garbage.
- Set keeps writing what it writes; only `jit vault link` (below)
  writes `storage: "op-ref"`. Rotation semantics for a reference are
  "the reference changed", which is re-linking, not a value rotation —
  1Password owns value rotation, and jit's per-path history archives
  old references, not old values. Stated plainly in the docs: history,
  `jit vault get` of an archived version, and export all operate on
  the reference for linked secrets.
- Provenance: a manual or bulk link stamps
  `Meta{Class: ClassOnePassword, Origin: ""}`. A new
  `ClassOnePassword = "1password"` is honest birth provenance ("born
  as a link"), flows through the class-AAD consent gate like every
  other class, and gives list/audit/status a display hook. A secret
  that `jit migrate` links (below) keeps its migrator's class
  (dotenv, mcp, …) — it was born in that file; `storage: "op-ref"`
  alone says how it is fulfilled. This is exactly why reference-ness
  is its own field and not a class. Origin stays empty for links made
  from nothing: Origin is plaintext on disk and the URI must not leak
  there — the encrypted payload is its only home.

## The resolver seam (mirrors KeyWrapper)

`internal/vault` gets no opinion about 1Password, exactly as it has no
opinion about keychains:

```go
// RefResolver resolves a reference-kind payload to the secret bytes it
// names. Schemes are dispatched by the resolver, not the vault.
type RefResolver interface {
    ResolveRef(ref string) ([]byte, error)
}
```

- `Vault` gains an optional `RefResolver` field. `Get`, after opening
  a `storage: "op-ref"` payload, calls it and returns the resolved
  bytes; every caller keeps calling `Get` and cannot tell the
  difference. A nil resolver returns a typed error
  (`ErrRefUnresolvable`) naming the reference kind, so surfaces that
  must never block on a GUI prompt can opt out by construction.
- The shipped implementation lives in a new **`internal/onepassword`**
  package (pure Go, no CGo, no new module dependency): it accepts only
  the `op://` scheme, rejects anything else, and execs the `op`
  binary. Scheme dispatch keys the door for a future second backend
  without building the abstraction now. op's query parameters pass
  through, and because resolution happens at every Get, a
  `?attribute=otp` reference yields a *current* TOTP each time — a
  feature, worth one line in the docs.
- Cost, stated up front: one `op read` is one process exec, roughly
  100–300ms, with no extra prompt inside an op session. A profile
  with a dozen linked secrets pays that a dozen times per resolve.
  v1 accepts it; if it hurts in practice, the follow-up is a batch
  method on the resolver (one `op inject` template resolving every
  reference in a single exec) driven from profile resolution — noted
  below, not built now.
- Wiring is centralized where vault construction already is:
  `openVault` / `openVaultFreshAuth` in `internal/cli`, and the
  service's vault construction in `agent.go`. `openVaultReadOnly`
  stays resolver-free (it never Gets).

### Executing `op` safely

- **Find**: `exec.LookPath("op")`, resolved once per process.
- **Verify before exec**: the resolved binary must carry a valid
  Developer ID signature from 1Password's (AgileBits') Apple Team ID,
  checked with the same technique `verifyStagedSignature` uses in
  `upgrade.go` (requirement string with the Developer ID marker OIDs
  and a pinned team ID, confirmed against the real binary during
  implementation). Fail closed, no override flag. The threat is a
  PATH-planted fake `op`: it never receives a secret, but it learns
  which references exist and can answer with attacker-chosen values;
  for a security tool the check is cheap and on-brand. `jit doctor`
  reports the state without prompting. op's own documented accepted
  risks (root, or an app with macOS accessibility permissions, can
  bypass its authorization while the app is unlocked) are the same
  same-user local-attacker bound `internal/keychainwrap`'s doc
  already states for jit itself — the adapter aligns two matching
  threat models rather than weakening either.
- **Invoke**: `op read -n <ref>`, no shell. The caller's environment
  passes through (op needs `HOME`, its config, `OP_ACCOUNT`,
  `OP_BIOMETRIC_UNLOCK_ENABLED`); jit sets nothing op-specific itself.
  stdout is the value, byte-exact. A nonzero exit surfaces op's stderr
  wrapped with a jit-side hint (see failure modes).
- **Waiting**: a read may block on the 1Password unlock dialog. Use
  the same generous timeout class as the Touch ID wait, with a plain
  progress line ("waiting for 1Password…") — the `🔐` glyph stays
  reserved for the Touch ID wait per the output contract. First use
  in a fresh session can cost two prompts back to back (jit's Touch
  ID, then 1Password's); both sides session-cache, so steady state is
  zero or one. Dogfood this before shipping — it is the UX risk.
- **Multi-account**: the URI does not name an account. v1 defers to
  op's own selection (`OP_ACCOUNT`, app-integration chooser) and
  records this as an open question rather than inventing per-link
  account storage speculatively.

## Command surface

```
jit vault link <vault-path> <op://vault/item/field>
```

The only new verb. It validates the URI shape, resolves it once
through the real resolver (proving op is installed, signed, signed in,
and the item exists — and costing the one prompt the user expects at
setup time), then writes the v4 reference envelope with
`ClassOnePassword`. `--no-verify` skips the trial resolve for offline
setup. Re-linking an existing path follows the overwrite-confirmation
convention (`-y`/`--yes`).

Existing commands change display only:

- `jit vault get` resolves and prints the value (that is the point);
  `--format json` adds the reference URI alongside the usual
  provenance. `jit vault list -l` and `jit status` tag linked entries
  with the plain-text class name, no new glyphs.
- `jit vault link --verify [path...]` re-resolves references on
  demand. `jit doctor` stays prompt-free: it checks the op binary's
  presence and signature and counts linked entries, but never
  resolves (doctor's auth-free guarantee holds).
- `jit vault export` exports the **reference**, never the resolved
  value: export is a vault backup, not a 1Password exfiltration. The
  export doc says so explicitly. A pleasant side effect: an exported
  reference imported on a second Mac resolves there as soon as op is
  signed in — linked secrets are the first vault entries that move
  between machines without moving any secret bytes.

## Automatic linking

Typing one `jit vault link` per field does not scale past a handful
of secrets, and it is not where the adapter earns its keep. Two
automatic flows, both built on the same enumeration primitive:
`op item list --format json | op item get - --format json` returns
every item's fields in one authenticated invocation, filterable to
`type=concealed` — one 1Password prompt per run, values held in
memory only, nothing written anywhere.

References produced by either flow are stored in **ID form**
(`op://<vault-id>/<item-id>/<field-id>`), not name form: 1Password
item and vault IDs survive renames, and a rename must not silently
break every link. The syntax docs support this explicitly — any
reference segment may be an ID, and segments whose names fall
outside the reference charset (alphanumeric, `-`, `_`, `.`, space)
MUST be — so ID form also sidesteps every quoting and encoding
question a title like `Stripe (prod)` would raise. The friendly name
lives where it already does, in the jit vault path.

### Bulk link: `jit vault link --from-op [--op-vault <name>]`

Enumerate the chosen 1Password vault (secret-bearing categories:
API Credential, Login, Password), take each concealed field, and
propose a jit path per field: `<item-title>/<field-label>`,
normalized to the vault path charset, single-field items collapsing
to `<item-title>`. Secure Notes are excluded in v1: a note's body is
`notesPlain`, not a concealed field, so admitting the category would
either link nothing or link prose; PEM-keys-in-notes is a real
pattern and an open question, not a v1 accident. Every run mints one
`GroupID` per 1Password vault (the vault is the source), so "these
40 came from the dev vault" survives any later renames, exactly as
migrate groups do. Then the house pattern: plan → [y/N] → write.
Rules, all fail-safe:

- An entry already linked to the same reference is "up to date" and
  skipped — re-running `--from-op` IS the sync, and it is idempotent.
- An existing entry with different content (a literal secret, or a
  link elsewhere) is reported and left alone; `--yes` does not
  override this one, a name collision with a real secret is a
  decision, not a confirmation.
- Title/label collisions after normalization are reported and
  skipped, with the `jit vault link` one-liner to resolve by hand.
- `--prefix <p>` namespaces everything under `p/` for users whose
  1Password vault names collide with existing jit paths.

### Migrate dedupe: link instead of copy (phase 2, plan verified against the code 2026-08-17)

The sharper flow, and the one that ships first. When the 1Password
CLI is installed, every `jit migrate` run dedupes against 1Password
by default: any secret it is about to vault whose value byte-exactly
matches a concealed 1Password field is stored as a reference to that
field instead of as a literal copy. The file is neutralized
identically either way, and no second copy of the value is created.
Opt-OUT (`--no-1password`), not opt-in: the user already opted in by
installing `op` and signing in, and a flag nobody discovers is a
feature nobody has. No `op` on PATH means the whole path is inert.

Matching compares the value the migrator parsed (after its own
unquoting) against the field bytes, byte-exact, no trimming or
normalization: a near-miss silently linking the wrong credential is
far worse than a miss that falls back to a local copy. Values
shorter than 8 bytes never match (a `PASSWORD=admin` line must not
link to whichever item also says "admin"). A value matching several
fields links to the first under a deterministic order (vault id,
item id, field id) — same value, same secret; the choice is
cosmetic. No match falls back to today's behavior, a local literal.

A migrated value that already IS a reference (`FOO=op://…` in a
`.env` kept for `op run`) links verbatim. Verified against the code:
today migrate would vault the literal `op://` string and `jit run`
would deliver it unresolved, breaking the workflow being migrated —
the dedupe hook turns that file into linked entries that keep
resolving. `jit scan` already treats `op://` values as non-secrets
(verified live), so scan and migrate agree.

**Where each piece lives**, verified against the real seams:

- **The intercept is a vault hook, not 23 edited call sites.**
  `vault.Vault` grows `LinkOnSet func(path string, value []byte,
  meta Meta) (ref string, ok bool)` beside `OnSet`, consulted by
  `SetWithMeta` (never by `SetReference`, never for
  `IsBackupPath` paths — whole-file backups are jit's copies, not
  credentials). Returning a ref stores a reference envelope with the
  MIGRATOR'S meta: class stays `dotenv`/`aws`/…, `storage` alone
  marks linkedness, exactly the provenance model above. All 23
  `SetWithMeta` call sites across 19 Apply paths stay untouched,
  the same reasoning that put `OnSet` on the vault.
- **`OnSet` still fires with the ORIGINAL plaintext on a linked
  write** — the agent-cache sweep hunts copies of the real value,
  which was on disk regardless of where the vault now points. A
  reference envelope write never reports the `op://` string to
  `OnSet`; a reference is not a credential the sweep should hunt.
- **The match list prints in the mutation log, not the plan.** The
  plan renders BEFORE `openVault()` by explicit design (declining
  must never cost a Touch ID prompt), and the same holds for
  1Password's authorization dialog, so the plan cannot contact `op`.
  The plan (and `--dry-run`, same rendering path, parity preserved)
  carries one announcement line when `op` is on PATH; the bulk fetch
  runs after [y/N] and Touch ID, behind a stderr cue in `jit vault
  link`'s wording, and the per-secret `path → reference` rows print
  as a `[1Password]` block in the mutation log.
- **Fail open, say so.** A signed-out CLI, a locked app, a timeout,
  or unparseable output degrades to literal copies with one amber
  note naming op's first error line. Migrate must never break
  because 1Password is broken.
- **The index holds hashes, not values**: SHA-256 of each concealed
  field → its reference, built from one
  `op item list --format json | op item get - --format json`
  enumeration (one authorization, values in memory only, raw JSON
  wiped after parsing). Stored references are built in ID form from
  the item JSON's own vault/item/field ids; the mutation log
  displays the name form, which is what the user recognizes.

This closes the loop the issue is really about: a 1Password user's
`.env` is usually a hand-made plaintext cache of things 1Password
already holds. Scan finds it, migrate replaces it with pointers, and
the drift-prone copy is gone from disk without 1Password ever being
written to.

What "automatic" does NOT mean: no daemon watches 1Password for new
items, and nothing links without the plan/confirm step. Re-running
migrate or `--from-op` is the refresh.

### Scan nudge (with the dedupe, scoped down)

Scan stays promptless and read-only, so it can never value-match
against 1Password; that nudge lives in migrate alone. What scan CAN
say textually: when a reported `.env` file also carries `op://`
reference values, the file's entry notes how many, and that migrate
keeps them linked. No new finding type, no schema change — a
rendering-only note on findings that already exist, `EndLine`'s
precedent. A file that is ALL references produces no findings and
stays unreported: nothing is exposed, and scan does not advertise.

## Interaction with the agent, grants, and mounts

Nothing about the decision points moves:

- **Consent / class AAD**: unchanged — the gate fires at DEK unwrap
  of the reference envelope, binding whatever class the envelope
  carries (`1password` for born-as-link entries, the migrator's
  class for migrate-linked ones), identically in both wrappers.
- **Process grants**: grant creation pre-unwraps wrapped DEKs exactly
  as today; what the serve path then decrypts is the reference, and
  resolution runs wherever `Get` runs.
- **Decoys need no resolution, verified**: mount decoy content is
  built from the profile's variable NAMES alone — `DecoyValues` never
  reads a value, by documented design (`mountmanager.go`). So an
  unauthorized reader `cat`-ing a mount can never trigger an `op`
  exec, and linked secrets change nothing on the decoy path.
- **Mounts already have the right shape**: the service resolves real
  content EAGERLY at unlock/refresh (`resolveReal` → `setRealIfGen`)
  and serves granted reads from memory, invalidating on session lock.
  For linked secrets that means the `op` calls fire at the unlock
  moment — right after the user's Touch ID, when they are provably
  present — not at read time. The residual caveat is narrow: a
  refresh landing while 1Password is locked (or its exec failing)
  must bound its wait, keep the mount on decoys, record the failure
  via the existing `lastResolveErr` / serve-audit path, and retry at
  the next unlock — fail closed, never a hung FIFO reader.
- **The service has no tty, and op's session model is tty-keyed.**
  op's authorization is scoped to a terminal session (tty + start
  time on macOS). jit's CLI-side resolves inherit the user's own
  terminal session, so an already-authorized terminal pays no extra
  prompt. The launchd service is different: its op invocations get no
  terminal session to ride, so each unlock-time refresh may need its
  own biometric authorization, with the prompt naming the jit service
  as the asking process — honest disclosure, but it must be verified
  on a real Mac before the mount path ships, and it is the strongest
  argument for the batch-resolution follow-up (one authorization per
  refresh, not one per secret). One genuine symmetry helps: 1Password
  revokes all CLI authorization when the app locks, the same moment
  jit's own screen-lock trigger drops its session — the two tools
  fail closed together.

## Failure modes

Each gets a one-clause error plus the one command to type:

- op not installed → `brew install 1password-cli` (or the app's CLI
  toggle).
- op present but unsigned/wrong team → refuse to exec, name the path.
- Not signed in / app integration off → surface op's stderr, hint
  `op signin` and the app's Developer settings toggle.
- Item or field deleted in 1Password → op's error names the missing
  piece; `jit vault link --verify` finds these in bulk.
- Reference entry opened by a jit built before v4 → the existing
  "newer than this jit understands, upgrade jit" path already covers
  it, unchanged.

## Out of scope for v1 (recorded, not forgotten)

- Writing to 1Password (`jit migrate --to-1password`, push-on-set).
- Service-account / headless resolution.
- Batch resolution (one `op inject` exec for a whole profile) — only
  if per-reference exec latency proves annoying in practice.
- Secure Note linking (PEM keys stored in note bodies).
- Per-link account pinning for multi-account users.
- Other backends (the scheme-dispatched resolver leaves the door
  open; nothing else is built).
- `jit scan` awareness of `op://` references already sitting in
  config files (cheap to detect, natural nudge toward
  `--link-1password`; a later increment).
- Any daemonized 1Password sync; manual re-runs of the bulk/migrate
  flows are the refresh.

## Dogfood findings (2026-08-17, live account, phase 1 build)

Exercised end to end against a real signed-in 1Password desktop app:
link (name form and ID form), get, get --format json, rotation in
1Password reflected with no re-link, byte-exact resolution of a value
containing quotes, backticks, `$VAR`, double spaces, and emoji
(delta vs `op read -n` was exactly vault get's display newline; the
JSON channel matches op byte for byte), `jit run` env injection,
literal-set-over-link clearing storage while keeping birth class,
history archiving the reference and restore turning the path back
into a link, dead links failing with op's own item-not-found error,
and malformed references failing before any prompt.

Two UX facts confirmed: the first use costs exactly the predicted
double prompt (jit Touch ID, then 1Password's "Allow iTerm2 to get
CLI access" dialog naming the process and account), and every op call
after that rode the 1Password session silently while jit's fresh-auth
commands kept prompting per their own policy. Still untested: the
background service's op session behavior (no linked secret has been
mounted yet), and 1Password-app-locked failure at refresh time.

`jit audit` captures the whole story with no new code: every link and
get is a command record with caller attribution, failed resolves keep
op's full error text, and a `jit run` against a linked profile shows
the unlock event with the secret's path beneath it. Two notes. The
audit log necessarily contains reference URIs — they appear in the
command line the user typed and in op's error text; that is command
recording working as designed, and the log is local, but it is why
ErrRefUnresolvable still keeps the URI out of arbitrary error
surfaces. And a SUCCESSFUL resolve is not marked as
"via 1Password" — the command record is identical to a literal get,
with the class/storage fields in `vault get --format json` as the
tell. An explicit resolve audit kind is a phase 2 candidate, not a
gap in the trail's honesty.

## Dependencies and testing

Zero new Go modules: the integration is an exec boundary, consistent
with the supply-chain stance, and gets a TECH_STACK.md §2 entry naming
`op` as a trusted-and-verified external binary.

Tests: envelope v4 round-trip, AAD tamper cases, and
rekey-carries-storage in `internal/vault`; `internal/onepassword` driven against a fake `op`
script on PATH (exit codes, stderr, newline handling, scheme
rejection, plus canned `item list`/`item get` JSON exercising the
bulk-link and migrate-dedupe plans, including collision and
already-linked cases); signature verification against the real binary exercised
in the attended QA pass on a real Mac, alongside a live end-to-end
`link → run → mount` dogfood.
