# Scan and Protect: one side looks, one side acts

**Status:** principle, 2026-09-21. Drawn from the agent-cache visibility
work of that day (the pattern sweep in `internal/audit/agentcachepatterns.go`
is its first application). It is the frame the next three pieces are
measured against — the Protect dialog, the deep scan, and any growth of the
vendor-pattern table — and the frame a new category or a new verb has to
fit before it is built.

Five promises this page makes:

1. **Scan never writes.** At any depth, under any flag. `jit scan` is the
   product's only surface that looks, and looking is all it does.
2. **Every finding names one Protect verb** — migrate, wrap, clean — or says
   plainly that only the user can act. A finding is counted toward the
   score only when jit stands behind both the match and the verb.
3. **Protect names everything it changes**, including what it changes
   outside the file the user pointed it at, and what it could not change.
   Nothing a scan showed may disappear because Protect quietly did more
   than it said.
4. **The vault is a source Scan may read, never a thing Scan touches.** A
   deep scan reads the vault's values to know what to look for; it still
   writes nothing, and no value reaches its output.
5. **Doctor reports the health of the protection, never a secret.**

## The two sides

|            | **Scan** — looks                                 | **Protect** — acts                              |
|------------|--------------------------------------------------|-------------------------------------------------|
| does       | reads and reports; changes no file               | migrate a file, wrap a tool, clean or redact the caches |
| needs      | nothing; deep: Touch ID *to read* the vault      | Touch ID, because it writes                     |
| output     | a finding: secret or vendor · file · line        | a result: what changed, what it could not       |
| runs       | on a schedule, unattended                        | when the user presses the verb                  |

Doctor stands beside them (`jit doctor`): profiles resolve, mounts serve,
the service runs this build. It opens the vault read-only with no key
wrapper (`openVaultReadOnly`), so it cannot decrypt, so it never prompts —
and that is why it can never be the thing that finds a secret.

## What Scan looks at

One command, eleven categories (`internal/audit/scan.go`, the trail), each
producing one finding type that names its verb:

| Scan looks at                                  | finding                 | verb              |
|------------------------------------------------|-------------------------|-------------------|
| `.env` files                                   | `env_file_present`      | migrate           |
| shell configs (`.zshrc`, …)                    | `shell_config_secret`   | migrate           |
| credential files (`~/.aws`, kubeconfig, …)     | `credential_file`       | migrate           |
| MCP configs                                    | `mcp_embedded_secret`   | migrate, or only you |
| private keys                                   | `private_key_risk`      | only you          |
| IaC files (tfvars, Kubernetes manifests)       | `iac_variable_file`     | migrate, or only you |
| wrappable CLI tokens (claude, gh, cursor, …)   | `wrappable_cli_token`   | wrap              |
| SOPS age keys                                  | `sops_age_key`          | migrate           |
| tokens by shape — files, and agent caches      | `exposed_secret`        | only you, or redact |
| shell history                                  | `shell_history_secret`  | migrate           |
| AI agent stores and caches                     | `agent_cached_secret`   | clean             |

The verb is stamped once, centrally, in `annotateRemedies`
(`internal/audit/remedy.go`), so every renderer and the app read the same
answer. `remedy: "manual"` is the honest "only you"; the human report's red
section and the app's "Only you can fix" card are that verb's home.

**Wrap is the model.** `ScanWrappableCLITokens` (`internal/audit/wrapcli.go`)
finds a tool's key with wrap's own catalog and extractors, so "a token this
scanner can see is by construction one wrap can move." `jit wrap <tool>`
vaults the key, installs the shim, and scrubs the token line out of the
tool's file (`internal/wrap/scrub.go`); the next scan does not see the key
because the key is gone. The finding disappears for the right reason. Where
detection and remediation can share code, they must.

**A finding without a verb says so.** Tool-minted logins — `gh`, `gcloud`,
anything that writes its own token file and will write it again at the next
login — are reported, deliberately not counted (`toolMintedLogin`,
`internal/audit/selfrotating.go`), and shown as "rotates itself". No button
is offered that would fix nothing.

## The surfaces

Every window and panel row answers one question, shows one kind of fact,
and offers one verb. A fact has one home; a second window that shows it
links there. Three columns, not two: Scan and Protect are the **at-rest**
side, wrap is the **tool** side, and Decoys, Grants and Asking are the
**runtime** side, what the protection does while a program is running.

| Surface | The question | What it shows | Verb |
|---|---|---|---|
| **Findings** (D9) | What is still in the open? | Every scan's results, the schedule (last run, next run, what is new) | Protect, Clean Caches, Scan Now |
| **Vault** | What have I protected? | Secrets by project, history, backups | Add, Link, Export |
| **Protected** (panel row) | How far along am I? | The score, `12 of 15 · 80%`, and when the last run was | opens Findings |
| **Tools** | Which commands on this Mac run through jit? | Each CLI's wrap state: wrapped, broken shim, session expired, key in the open | Wrap, Repair, Log In, Unwrap |
| **Decoys** | Did something read a protected file it should not have? | Reads in the last 24 hours by a program no run or grant covered: which file, which program | opens Audit, filtered |
| **Grants** | Who may read real values now, and until when? | Active grants: program, expiry | New Grant, Revoke |
| **Asking** | Is something waiting on me this second? | The live consent request | Allow, Deny |
| **Doctor** | Is the protection machinery healthy? | Profiles resolve, mounts serve, the service runs this build. Never a secret (D4) | Repair |
| **Audit** | What happened? | The log | filter |
| **AI Agents** (D10) | What is this agent doing on my Mac? | One row per agent, one line of facts, each linking to its home: key state (Tools), cached copies (Findings), reads today (Decoys), grant (Grants) | none of its own; a digest |

**How a scheduled run is heard.** A run that changes nothing is silent. A
run that finds something new is announced once, through the "notify on
changes" switch: "Sunday's scan found 2 secrets in the open", naming them,
and opening Findings. The Protected row carries the day of the last run;
the Findings header carries the rest. Today the only notification is for
new cached copies and it opens AI Agents; both change.

## The one bridge: deep scan

Scan recognises a token by its shape. It cannot know that `hunter2-prod` is
the database password; only the vault knows that. So a deep scan
(`jit scan --deep`) adds the vault's values as exact-match needles to the
same search, and reports each hit by **vault variable · file · line**. That
reaches the two things shape cannot: a formatless secret, and a copy whose
origin the user has already protected.

Its rules:

- It is still Scan. It writes nothing. Its Touch ID is to *read* the vault,
  and the sheet says so ("Touch ID follows", nothing more).
- It opens the vault through `openVault()`, the session-reuse path: no
  prompt when the vault was unlocked recently, one prompt when it was not.
  Not `openVaultFreshAuth()` — that path is for commands about to write.
- The values live in memory for the search and never reach the output. A
  deep finding carries the vault variable's *name*, the file and the line;
  the app runs `jit scan --deep --format json` and reads names and
  locations, never a value (the app never handles plaintext).
- It is opt-in. The scheduled scans that keep the menu-bar dot honest stay
  regular, so a background scan never interrupts anyone.
- **It searches for the vault's secrets, not for everything in the vault.**
  `jit migrate` vaults every variable of a `.env` — ordinary configuration
  too, so the pointer file stays complete — so a vault is routinely half
  endpoints, ids and paths. The needles pass the scan's own name and value
  gates before the search, and the summary says how many entries were left
  out. See D13.

Read-only and authenticated is a new combination for jit: `jit scan`
was unauthenticated by design, `jit migrate caches --dry-run` was
authenticated but a preview of a write. Deep scan is the check those two
were each half of.

## Where the line was crossed, and what fixes it

The session that produced this page began with: "when I click Protect on
the .env file, it also clears the AI agent cache alerts." Four things had
crossed the line, one of them correctly.

1. **Protect did a scan-shaped thing without saying so.** `jit migrate`
   sweeps every agent cache for copies of what it just vaulted
   (`internal/cli/migrate.go`, `CleanAgentCaches`) — a fine act — and the
   sweep's result changed what the next scan showed. The user experienced
   the act as alerts vanishing. **Fix (Protect side):** the Protect dialog
   names the copies it will remove and the ones it cannot ("also removes 9
   copies from Claude Code's transcripts; 1 in Cursor's chat database it
   can't"). `StatusItemController+Scan.swift`, `protectPlan`.
2. **Scan went blind after Protect.** A cached copy was found only by
   cross-reference (`crossReferenceAgentCaches`,
   `internal/audit/agentcache.go`): search the caches for a value some
   finding confirmed. Once the `.env` held a `jit://vault/` pointer there
   was no value to search for, and a copy the sweep had skipped — an agent
   was writing the file, or the store is binary — stayed on disk and left
   the report. Measured 2026-09-21: found before the migrate, found by
   nothing after. **Fix (Scan side, built):** the vendor patterns swept over
   every agent cache root by shape, in the same walk, with each regex
   reduced to its literal lead so the pass costs seconds, not minutes
   (`internal/audit/agentcachepatterns.go`).
3. **A persisted note between the sides was tried and rejected.** A
   breadcrumb Protect left for Scan to repeat ("2 copies in Cursor's chat
   database") could name neither the secret nor the line — by the privacy
   rule that keeps jit's state files free of values and paths. A fact the
   reader cannot act on precisely is noise. Reverted the same day. The rule
   it leaves: **Scan reports what it finds, fresh, from the file.** It never
   repeats a summary Protect wrote down.
4. **`jit migrate caches --dry-run` was being used as a check.** A Protect
   command wearing Scan's hat, which is where "should doctor find secrets?"
   came from. Deep scan is the check; `jit migrate caches` (Clean Caches in
   the app) is the act; doctor stays out.

## Rules for the next category, and the next verb

A candidate belongs to **Scan** when it only reads. It needs, before it
ships: a `record_id` from file, key and type; a line where one exists; a
verb from `annotateRemedies`; a decision on whether it counts
(`CountedAsSecret`); and, if it is a token shape, a hard literal prefix — or
an anchor in `patternAnchors` — plus a test vector. A shape with no fixed
bytes to look for is not admitted, however common the vendor; that is why
jit's table is 114 formats and not four hundred (fifty-five until 2026-09-21; the sixty-odd verified prefixes recorded that day were admitted by this rule, and the shapes with no fixed bytes among them are matched in files only).

A candidate belongs to **Protect** when it writes. It must be one jit
command the CLI can run on its own (the app is never the only way to do
something); it must print what it changed and what it could not; its plan
(`--dry-run`) must be the thing the real run commits to; and if it touches
anything beyond the file the user named, the confirmation says so before
Touch ID.

Neither side may change the other's view silently. When an act removes
what a scan showed, the act says so; when a scan cannot see what an act
left behind, the scan is what gets fixed — not by a note, but by looking.

## Decisions

- **D1 — Scan is read-only in every mode, and unauthenticated except to
  read the vault under `--deep`.** `internal/audit/doc.go`'s guarantee
  stands; deep adds a read, never a write.
- **D2 — Deep is opt-in and reuses the session.** Scheduled scans are
  regular. Deep prompts at most once, and only when the vault is locked.
- **D3 — No persisted notes between the sides.** The breadcrumb is gone
  and stays gone. A finding is generated from the file at scan time or it
  is not a finding.
- **D4 — Doctor never finds or reports a secret.** It stays prompt-free.
  The `--vault` variant considered on 2026-09-21 is dropped in favour of
  deep scan.
- **D5 — A finding with no verb is reported, marked, and not counted.**
  Tool-minted logins are the standing example; the rule is general.
- **D6 — The vendor table grows only by hard prefix or anchor.** Breadth
  is orthogonal to this frame. Sixty-odd verified gaps are recorded
  (2026-09-21) and admitted on that rule, when wanted, never as a
  substitute for the two fixes above.
- **D7 — Protect's confirmation is the fix for the original report**, not
  a cleverer scan. The dialog names the cache copies it will and will not
  remove. Small, Protect-side, first.
- **D8 — Deep is offered only once the vault holds a secret.** An empty
  vault has nothing to search for, so Deep would be a Touch ID for
  nothing. The depth row stays visible and disabled with its reason, and
  names the live count when enabled ("the 14 secrets you've vaulted").
  Gate: the vault secret count the app already reads from `jit status`.
  Decided 2026-09-21.
- **D9 — The app's Scan window is named Findings.** A window called Scan
  reads as "press here to scan"; it is also where the scheduled scan has
  always put its report (the panel's Protected row and the cached-copies
  notification read the same report), and nothing said so. Named for what
  you look at, as Doctor, Vault and Settings are, it owns the schedule:
  last run, next run, what is new since. "Scan" stays the verb on its
  buttons (Scan Now…, Scan Whole Mac…) and the CLI keeps `jit scan`.
  Scheduled runs are regular depth; Deep is by hand. Decided 2026-09-21.
- **D12 — Redact is the Protect verb for a shape-found token in an agent
  cache, and it takes no backup.** `jit migrate redact` replaces the span
  with `<jit:redacted:VENDOR>`, the marker the value sweep writes with a
  variable's name, and touches only agent caches. No vault, no backup, no
  Touch ID: a backup would put an agent's whole transcript in a vault the
  user never chose for it, and needing the vault is what would stop the
  automatic run after a scheduled scan. The marker is the record; the
  change is one-way and the plan says so. Nothing is deleted — a
  transcript is one record per line. The app offers it on a row (Redact…),
  on the card (Redact All…), and, under an opt-in switch, after every
  scheduled scan; the scan itself still writes nothing. Decided
  2026-09-21.
- **D11 — A vault copy counts as an exposed secret, and the protected
  count stands.** Every `vault_copy` of one value is one exposed secret
  (they share a cause group), so the score falls by the copy. The
  protected count is not reduced: it counts vault entries behind live
  mounts, and a vaulted secret is not always one of those (a pointer
  file, a wrap-captured token), so subtracting would guess. Built
  2026-09-21 with `jit scan --deep`; the alternative — report, mark, do not
  count — kept the score flattering while a copy was loose.
- **D10 — AI Agents answers "what is this agent doing on my Mac", and
  acts on its own rows.** One card per agent: what is in its files (every
  finding the scan placed there — vault copies, cached copies, tokens by
  format — with Clean Caches and Redact, the same commands Findings runs,
  Redact narrowed to that agent's files), what it can reach (protected
  files through jit, whether a real value goes to it only after Touch ID,
  MCP keys in the open, grants), what it did this week (from the audit:
  runs, real values, decoy reads, prompts), its key, and its one setting —
  redact its caches after every scheduled scan. Every number is one
  Findings or the audit holds. *Revised 2026-09-22.* The first cut (decided
  2026-09-21) was a digest that owned no verb: one row, four facts, each
  linking to its home. It counted one finding type, said "all set" over
  34 copies in Claude Code's transcripts, and nobody noticed, because a
  digest nobody acts from is a digest nobody reads. An agent is not a tool:
  it records, so the first row is what it has seen. jit-app #45.
- **D13 — A deep scan searches for the vault's secrets, not for
  everything in the vault.** `Config.vaultNeedles` applies the same
  `NonSecretValueReason` / `NonSecretNameReason` pair every other scanner
  asks, so a vaulted endpoint URL, filesystem path or documented-public id
  is not hunted across the Mac. The premise it replaces — "the vault says
  what it is" — stopped holding the moment `jit migrate` began vaulting a
  whole `.env`: on a real machine (2026-09-22) 14 of 25 vault entries were
  configuration (`CAIDO_URL`, `WIZ_API_ENDPOINT`, `JAMF_PRO_URL`, three
  `*_CLIENT_ID`s), every hit a true exact match and none an exposure. This
  is the same overreach `EnvFileCacheNeedles` fixed one layer down (issue
  #79) with the same two gates: `eligibleNeedle` tests distinctiveness, not
  secretness. The gates stay narrow — a URL is excused only with no
  userinfo and no opaque segment, so a `DATABASE_URL` carrying a password
  keeps its place — and the filtering is never silent: the summary carries
  `vault_config_skipped`, the report prints it above the ledger, and
  `--unfiltered` searches for them all and tags each copy with the rule
  that would have hidden it. What the gates cannot reach — an admin email,
  a service-user id — is the user's call, and wants a mark on the vault
  entry, not a wider rule. Decided 2026-09-22.
- **D14 — The report opens with what to do, in the sections' own
  numbers, not with a ledger.** `jit scan` led with "YOUR SECRETS: 26 — 10
  protected by jit (38%)" and a ten-cell bar; the app's Findings window
  mirrored it as "10 of 26 secrets protected". The 26 were deduplicated
  secrets no section listed: on the machine that asked (2026-09-22) the
  sixteen "unprotected" were four vaulted entries with copies in the open
  and twelve tokens in Claude Code transcripts — none of them a thing
  `jit migrate` protects — and the honest answer to "which sixteen?" took
  a scan, `jq` and the engine's source. Both surfaces now open with the
  vault's own count ("25 secrets in your vault", read the way `jit status`
  reads it: names, no key, no prompt) and then one line per block below,
  in that block's own numbers and words, naming its command when it has
  one: "5 files hold secrets jit can move into the vault · jit migrate",
  then the red section's action blocks one each — "4 secrets · rotate,
  then clear the copy — the secret is already in your vault", "12 secrets
  · rotate — an agent kept its own copies". The app, whose cards are
  tiers rather than actions, says the same in its cards' numbers: "4
  still have plaintext copies in 32 files · clear the copies", "17
  flagged lines sit in 2 files of Claude Code's transcripts · redact
  them". The rule, held by tests on both sides: a number in the opening
  lines is a number a block (the app: a card) shows, and nothing is
  counted twice in two units. The percentages went with the ledger —
  "0% → 85%" on a section header had no denominator left to refer to —
  and so did the bar. A regular scan whose vault holds secrets is told what
  it did not look for, with `jit scan --deep` as the line's command.
  `secrets_total` / `secrets_protected` stay in the NDJSON for the score.
  Mockup: jit-app `docs/design/mockups/Findings-header.html`. Decided
  2026-09-22.

- **D15 — The panel's rows follow one rule, and the windows' headers
  share one shape.** A panel value is a number plus one or two words; its
  dot is the window's own mark, or nothing for a count; a green dot says
  why in words; red or amber is the worst fact, and the window names it.
  A window's header is the headline, then one line per thing to do in
  the numbers a card below shows, ending in the card's verb. Both rules
  are written in the design system's `windows.md` ("Panel rows", "The
  header's to-do lines"); the tests on `PanelValue` hold the first. The
  Decoys window (jit-app #45) and the Tools window (#46) were built on
  them; the panel (#47). Decided 2026-09-22.

## Known gaps the app now shows honestly

Found while building the three windows on a real Mac (2026-09-22). Each
is the engine's to close; until then the app says so in the row rather
than pretending.

- **`jit scan` does not ask the keychain.** A token in a tool's own
  keychain (`gh auth token`) is found only by `wrap list --discover`, so it
  is not a Finding; the Tools window carries it as the one before-fact
  that lives there, naming the command any program can read it with.
- **git through the `osxkeychain` helper reads as "nothing found".**
  Discovery asks export commands only for shim tools.
- **Serve events name no reader.** Every decoy read this week says
  "reader not recorded"; the audit's best-effort kernel lookup came back
  empty each time. The Decoys window prints that rather than "unknown".
- **Consent events carry no program.** The agent card's "prompts" count
  wants approvals and declines by the program that raised them.
- **A run that asks a mount for a variable the vault lacks is logged as an
  undelivered decoy serve** with the variable in its cause. The Decoys
  window reads it out of the cause string ("secret not found"); a typed
  field would be better than a regex.

## What this decides next

In order: the **Protect dialog** (D7; one sentence, closes the bug at its
source), then **`jit scan --deep`** (the vault as a source; builds on the
per-hit `AgentCacheCopy{Var, Line}` the sweep result now carries), then the
**vendor table** (D6, when wanted). The app's Findings window (D9) gains
the depth choice after scope — final mockup 2026-09-21, on the design
system.
