# Findings and Protect: the build plan

**Status:** built, 2026-09-21 (all eight steps, on branches `scan-agent-cache-patterns` in jit and `findings-window` in jit-app; D11 built as "count as exposed, protected stands"). Kept as the record of what was built and why. Implements `scan-and-protect.md` (D7–D10) and
the approved mockup, https://claude.ai/artifact/6S859C7vyFBfiy4XVoW5Jc
(eleven frames). Each step is one commit, gated the same way, and the
mockup is the thing each step is checked against — no drift.

Two repositories: `jit` (Go engine, CLI) and `jit-app` (Swift menu-bar
app). The app never sees a plaintext value; every fact it shows comes from
`jit scan --format ndjson`, `jit status`, or a command's structured result.

The gate for every step: `go test -race ./...`, `go vet`, `gofmt`,
`staticcheck@latest`, docs-gen with no drift; `swift build`, `swift test`;
then one pass over the frame it implements, side by side with the window.

## Step 0 — commit what is built

The pattern sweep is done and green but uncommitted. Commit it first so
every later step diffs against a clean base.

- `internal/audit/agentcachepatterns.go`, `agentcachepatterns_test.go` (new)
- `internal/audit/agentcache.go`, `internal/audit/finding.go` (0.22.0)
- `docs/reference/scan-ndjson.md`
- `design/scan-and-protect.md`, `design/findings-and-protect-plan.md`

Not in this commit, another session owns them: `internal/cli/migratecaches.go`,
`migratecaches_test.go`, `migrateplan.go`, `internal/migrate/agentcache.go`,
`agentcache_test.go` (the `AgentCacheCopy{Var, Line}` enrichment). Step 4
builds on them once they land.

## Step 1 — Findings (app) · frames 1, 3

The Scan window becomes Findings and owns the schedule.

**Rename.** `scanWindow` title in `StatusItemController.swift`; the panel's
"Run Scan" action → "Scan Now"; the "Scan" button in `AgentsView+Cards`
→ "Findings"; `Format.decoysFact`'s "protect a file in the Scan window";
Settings' scan section; README and website mentions. The CLI keeps
`jit scan`. Buttons carry the verb: "Scan Whole Mac…", "Choose Folder…",
"Scan Now…".

**The header owns the schedule.** `MenuModel` gains `macScanKind`
(`.scheduled`, `.byHand`, `.afterProtect`, `.deep`), set by whoever calls
`runScan`. The sub line is built by one `Format.findingsSub(...)` from:
kind, `macScanAt`, the next run (`macScanAt + scanSchedule.interval`, or
"schedule is off" with a Settings link), the new-since count, and the
existing home-folder limit sentence.

**New since the previous run.** `Notifier.cachedCopiesKey` (paths of
cached copies) generalises to the set of every counted finding's
`record_id` from the previous whole-Mac report, saved in UserDefaults on
each whole-Mac scan. `ScanReport.newFindings(known:)` returns the rows the
previous run did not have; the header counts them, each row carries the
"new" chip (`app-field`, `app-label-2`, no new hue). First scan ever: saves
only, marks nothing.

**Empty state.** "No findings yet · A scan runs on its own every <schedule>
and reports here. Run one now to see where you stand: …" — the schedule
word from `ScanSchedule`'s own label.

**Tests.** `ScanReportTests`: `newFindings` on first run / unchanged /
added / removed. `ScanScheduleTests`: next-run from last + interval, off.
`FormatTests`: the sub line for each kind. `ScanTiersTests` unchanged.

## Step 2 — a scheduled run is heard (app) · frame 10

**Notification for anything new.** `noteNewCachedCopies` becomes
`noteNewFindings`: after a whole-Mac scan, the counted findings whose
`record_id` the previous report lacked. Title "<Day>'s scan found N
secrets in the open" ("Today's" when it ran today); body names the first
two by `Format.home` and the copies by agent; click opens Findings
(`NotificationTarget.findings`, new). Silent when nothing is new. Under
the existing "notify on changes" switch. The cached-copies notification
folds into this one; its target stops being AI Agents.

**Panel.** The Protected row's value adds the day of the last run when it
was scheduled: "12 of 15 · 80% · Sunday". The row keeps opening Findings.

**Tests.** A pure `Notifier.newFindingsNotice(fresh:at:)` builder: 1 file;
1 file + copies; copies only; nothing → nil. Day word for today / this
week / older.

## Step 3 — the Protect dialog names the sweep (app) · frames 3, 4

The fix for the original report. No scan runs; the dialog reads the
report on screen.

`protectPlan` takes the copies from `model.scan` whose `originPath` is one
of `plan.migrate`, groups them by agent and cache area, and adds one
paragraph after the vaulted names:

> It also removes the 9 copies the scan found in Claude Code's
> transcripts and edit history. A copy it can't safely rewrite is left in
> place and named when it's done.

Built by `Format.protectSweepSentence(copies:)`; absent when there are
none. The copies card's note gains "Protecting the file they came from
removes them too." Wrap plans get no paragraph (wrap scrubs the tool's own
file; the sweep is migrate's).

The dialog stays an `NSAlert` for now; moving it onto the design system's
alert layout (plate, 440px) is a separate, app-wide change.

**Tests.** `FormatTests`: 0 copies → nil; 1 copy one area; 9 across two
areas of one agent; two agents ("in Claude Code's transcripts and in
Cursor's chat database").

## Step 4 — the result banner (engine + app) · frames 5, 6

**Engine: `jit migrate --format json`.** Today migrate's outcome is prose.
The app needs it structured, the way scan's is. Under `--format json`
stdout is one JSON document and the human text is suppressed:

```json
{
  "files":  [{"path": "~/notion/.env", "vars": ["NOTION_TOKEN"], "status": "migrated"}],
  "caches": {
    "removed": [{"agent": "Claude Code", "area": "transcripts", "path": "…", "copies": [{"var": "NOTION_TOKEN", "line": 214}]}],
    "left":    [{"agent": "Claude Code", "area": "transcripts", "path": "…", "kind": "live", "reason": "…", "copies": [{"var": "NOTION_TOKEN", "line": 118}]}]
  },
  "errors": []
}
```

Paths and variable names, never values — the same contract as scan's
ndjson. `kind` is `SkipKind`. Built from `AgentCacheCleanup` after the
other session's `Copies` lands. Documented in `docs/reference/`.

**App: the banner region.** `ScanReportView` gains the `WindowBanner` the
AI Agents window already has. `showResult` routes a Protect outcome to
`model.findingsOutcome` when Findings is the key window, instead of the
result sheet. Sentence from `Format.protectOutcome(_:)`: "Protected
~/notion/.env · NOTION_TOKEN is in the vault · 8 cached copies removed ·
1 left in Claude Code's transcripts". On the right: "What jit Did…" (the
verbatim sheet, as AI Agents does) and Undo, which runs
`jit migrate undo <path>` after its own confirmation — the confirmation
says undo restores the file, not the cache edits. The banner clears on
the next action. Then the window rescans (`macScanKind = .afterProtect`).

**Tests.** Go: golden JSON for a migrate with a sweep that removed 8 and
left 1 live; with no sweep; with an error mid-way (partial result still
reported). Swift: `Format.protectOutcome` for removed-only, removed+left,
nothing swept, two files.

## Step 5 — `jit scan --deep` (engine) · frames 8, 9

The one bridge. Read-only, authenticated only to read the vault.

**CLI.** `scan.go` gains `--deep`. It opens the vault through `openVault()`
(session reuse, at most one prompt), collects the values with
`migrate.CollectVaultSecrets`, and passes them in as
`audit.Config.VaultNeedles []audit.VaultNeedle{Var, Value}`. `audit` keeps
no vault import and stays unauthenticated on its own; the values are
inputs. A locked vault with no session and no Touch ID is a plain error
before any scan runs, never a silently regular result.

**Search.** Two passes, both exact-match through the existing
`substrIndex`:

1. Agent caches: `crossReferenceAgentCaches` adds the vault needles to its
   pins. The exact pass already reads binary stores, so the chat-database
   case is covered here.
2. Home files: the content sweep that runs `FindFileTokens` runs the same
   index over the bytes it already read. This reaches the formatless
   password in `~/scripts/backup.sh`.

A hit is `FindingTypeVaultCopy = "vault_copy"`: `key_name` = the vault
variable (`project/VAR`), file, line, `agent`/`cache_area` when in a cache,
evidence "an exact copy of a vaulted secret" + "(found in …)". Remedy:
`clean` in a cache, `manual` elsewhere. `SchemaVersion` 0.23.0;
`scan-ndjson.md` gains the type. No value is ever serialized (the
`rawValue` contract), and the progress label never names one.

**The score (decision D11, to confirm).** A vaulted secret with a
plaintext copy in the open is not protected. `Coverage` moves each
distinct variable that has a `vault_copy` from Protected to Exposed, so
"12 of 15" drops to "11 of 15" until the copy is cleaned. The alternative
— report, mark, don't count — keeps the score flattering while a copy is
loose. Recommended: count it.

**Tests.** Origin migrated to a `jit://vault/` pointer, copy left in: a
transcript (line named), a binary sqlite file, a shell script — `--deep`
finds all three with the variable name; regular scan finds only what
shape allows. ndjson output contains no needle value (assert on the raw
bytes). Locked vault without session → error, exit non-zero, no findings.
The cross-ref exact pass and the vault pass agree on a value present in
both (one finding, cross-ref wins, as the pattern sweep does today).

## Step 6 — depth, gate, deep in the app (app) · frames 2, 7, 8, 9

**Depth sheet.** "Scan Whole Mac…" and "Scan Now…" raise the sheet from
the title bar (frame 2/7): Regular / Deep as selectable rows, Scan as the
default button. Folder scans take the same sheet.

**Gate (D8).** The Deep row is choosable only when
`model.cli?.vault?.secretsStored > 0`; disabled it reads "Available once
your vault holds a secret — protect something first"; enabled it reads
"…exact copies of the N secrets you've vaulted… Touch ID follows."
Scheduled runs never pass `--deep`.

**Running.** `JitCLI.scan` gains `deep: Bool`. While a deep scan runs with
the service locked, the window shows the unlock state (frame 8), from
`model.state`; unlocked, it goes straight to the report.

**Report.** `ScanTiers` gains `.vaultCopies` for `vault_copy`, first in the
body: eyebrow "In your vault, still in the open", the variable in a
`KeyChip`, the file and line, the fact from the evidence; Clean… for
cache rows, Open for files. Header sub: "Deep scan, by hand · N are copies
of secrets you've already vaulted".

**Tests.** `ScanTiersTests`: `vault_copy` tiering and ordering. Gate logic
as a pure function of `secretsStored`. Sheet selection → arguments.

## Step 7 — AI Agents as a digest (app) · frame 11

`AgentsBoard` reduces to one row per installed agent with four facts in a
fixed order, each from its home:

- key: `ToolRecord.keyState(scan:)` (Tools)
- copies: `macScan.agentCopies(in:)` (Findings)
- reads today: decoy serves in the last 24 h by that agent's programs,
  from the audit query the Decoys row already runs, filtered by program
  (Decoys → Audit)
- grant: `model.grants` matched by name (Grants)

The dot is the worst of the four. One button in the action group, to the
home of the worst fact; none when all four are fine. The caches, MCP and
"What agents read" cards go; Clean Caches and Protect leave this window.
Footer: "Asking is on/off …" with Settings…. `AgentsView` drops its filter
(three rows need none).

**Tests.** `AgentsBoardTests` (new or extended): the four facts per agent;
worst-of dot; the link target; no agent installed → the existing empty
state.

## Step 8 — docs

`docs/design/windows.md`: Findings named among the medium windows; the
banner region's Undo caveat. `scan-ndjson.md` 0.23.0. README and website:
Findings, deep scan, the notification. `scan-and-protect.md`: D11 once
decided, and the "not yet drawn" lines removed.

## Order and why

1 and 2 first: cheap, app-only, and they make the schedule visible, which
is the question that started the last review. 3 next: the original bug,
closed at its source, app-only. 4 needs the other session's copies
enrichment and adds an engine surface, so it waits for that to land. 5
before 6: the gate is meaningless without the command. 7 last: it only
reads what the others produce.

## Known and accepted

- Fixture-shaped tokens printed in a Claude session read as real findings
  in its transcript. Only `--exclude` covers it; a per-finding ignore is
  not in this plan.
- The Protect dialog stays an `NSAlert`; the design-system alert layout
  is app-wide and separate.
- Undo in the banner restores the migrated file only; the cache edits have
  their own undo command, which the "What jit Did…" sheet names.
