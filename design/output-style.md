# jit output style

The house style every jit command shares, so the whole tool reads as one
tool. The instincts are borrowed from `gh` and `docker`: structure comes from
**whitespace and weight**, not box-rules; a leading **glyph** carries the
state so the eye finds it before the words; **color is strictly semantic**,
never decorative.

Every ink and every glyph is defined in **`internal/style`**, one package
below `cli`, `audit` and `ui` so all three share it (`internal/cli` imports
`internal/audit`, so the vocabulary could not live in `cli`).
`internal/cli/style.go` re-exports it under short local names — `cBold`,
`cPath`, `cOK`, `cWarn`, `cRisk`, `cWarnBold`, `cPathBold`, `cOKBold`, the
`glyph*` constants, `flowNames`. Never build a colour at a call site:
`TestPaletteIsCentralised` and `TestNoHandRolledColors` both fail on it, and
the point of the seam is that a repaint is one edit.

Typing a glyph literal at a call site is the same mistake, and `TestNoGlyphLiterals`
fails on it. It tokenizes with `go/scanner`, so a glyph in a COMMENT is prose and
stays free; `_test.go` files, `style.go` and `markdown.go` (a markdown document,
not terminal output) are exempt, and `GlyphMark` (`!`) is excluded as ordinary
punctuation. This paragraph long claimed `TestPaletteIsCentralised` covered
glyphs, which it never did — the check now exists for real.

## The whole palette

Six inks and one attribute. There is nothing else — no blue, no magenta, no
background colors, no 256-color or truecolor values, and **no dim/faint**.
If a line needs to stand apart and none of these fits, the answer is
whitespace or wording, not a new color.

| Ink | Helper | Means | Use it on | Never on |
|---|---|---|---|---|
| green | `cOK` | this is fine / this is done | `●` and `✓` glyphs, "N protected by jit (62%)", the filled `▰` of the coverage bar, "· wraps docker" | a command; a heading that isn't reporting good state |
| green + bold | `cOKBold` | the one headline good state on the line | `jit will protect these`, the coverage arithmetic `62% → 81%`, `+19%` | more than once per line |
| amber | `cWarn` | needs a look, nothing is broken | `○` glyphs, "unreferenced", decoy notes, the manual-remainder `+18%` | a sentence of plain advice — that reads as a warning state it isn't |
| amber + bold | — | an amber state marker that must be found first | the `!` leading a non-critical manual group, `INCOMPLETE SCAN`, `81% → 100%` | body prose |
| red | `cRisk` | a real problem the reader must act on | `✗`, `HIGH`, the `!` on a critical group | anything the reader can't do something about |
| red + bold | `cRiskBold` (`style.RiskBold`) | the section header naming what only the user can fix, and `CRITICAL` | `only you can protect these` | individual items inside a red-bold section |
| cyan | `cPath` / `cPathBold` | **something you can type or open** | every command, always via `hlCmds`; the `→` that introduces one; runnable spans inside a sentence | a path the report is merely describing (that's plain) |
| **bold** | `cBold` | the single primary thing on this line | a group name, a manual-group title, `YOUR SECRETS: 80` | two things on one line — then neither is primary |
| plain | *(no helper — just `fmt`)* | everything else, primary or secondary | body prose, action sentences after the `→`, manifest paths, counts, origins, timestamps, hints, footers | — |

**Secondary text is plain, not dim.** jit rendered everything secondary with
`ESC[2m` until 2026-08-06. Most terminals draw that at roughly half opacity,
and because secondary is the *majority* of a report — all 14 manifest paths,
every address in the manual section, every count in `jit status` — the effect
was a tool whose main surface had to be squinted at on a dark theme. Hierarchy
now comes from bold and from semantic color; secondary text simply doesn't
take either, and recedes by contrast with the lines that do.

Do not reintroduce faint for one line. It only functions as a level of
hierarchy if it is applied consistently, and applied consistently it is the
readability problem again. `TestNoFaintText` in `internal/cli/outputstyle_test.go`
enforces this across `internal/` and `cmd/`, tests included.

## The whole glyph set

Every symbol jit draws, and the one ink each takes. A glyph in the wrong ink
is a line that lies at a glance, so the pairing is part of the definition.

| Glyph | Const | Ink | Appears on | Not for |
|---|---|---|---|---|
| `●` | `GlyphOK` | green | a row whose state is healthy: running, wired, serving real to a grant | anything the reader must act on |
| `○` | `GlyphWarn` | amber | a row whose state needs a look: unreferenced, decoy, locked session | a findings-list item — that's `!` |
| `✗` | `GlyphRisk` | red | a row whose state is a real problem: failed check, critical finding | a problem the reader can't fix |
| `✓` | `GlyphDone` | green | an action that completed (`✓ Scanned .env files`) | a state that merely *is* healthy — that's `●` |
| `!` | `GlyphMark` | amber bold, red bold when critical | an **item** in a findings list the reader must fix themselves | a dashboard row |
| `→` | `GlyphAction` | cyan | the one thing to type, on its own line, last in its block | more than once per state |
| `→` | *(inline)* | plain | "maps to" inside prose: `AWS_KEY → ~/.aws/credentials`, `62% → 81%` | starting a line — that reads as the action arrow |
| `•` | `GlyphBullet` | plain | a list item with no state of its own | anything colored — color would claim a state |
| `└` | `GlyphBranch` | plain | evidence hanging off the item above: the matched rule, why a gate kept it | a tree of paths — `vault list` indents instead |
| `▰ ▱` | `GlyphBarFilled` / `GlyphBarEmpty` | green / plain | the ten-cell coverage bar, one cell per 10% | any other progress — nothing else has a denominator |
| `─` | `GlyphRule` | plain | the single subtotal line under a numeric table | section dividers, borders, boxes |
| `🔐` | `GlyphLock` | plain | the stderr line announcing a blocking Touch ID prompt | anything else; this is the only emoji jit prints |
| braille | `SpinnerFrames` | plain | a step still running, replaced by `✓ <text>` when it settles | a step that finished |

The state glyphs (`●○✗✓`) answer *what is this line's condition*. `!` answers
*is this mine to fix*. A line with no state gets no glyph — adding one to make
it "look consistent" is what let a real warning hide under a green `●` row
once, read as part of it.

Severity words in the full report (`CRITICAL`, `HIGH`, …) are colored text,
not glyphs, and the markdown export uses emoji circles — a different format
with different constraints, not the terminal vocabulary.

## The severity ladder

Severity is told apart by what its ink MEANS and by the word — never by how
yellow it is.

| Rung | Ink | Reads as |
|---|---|---|
| `CRITICAL` | red bold | a live credential, act now |
| `HIGH` | red | almost certainly a credential |
| `MEDIUM` | amber | secret-shaped, unconfirmed |
| `LOW` | plain | a broad match, probably fine |
| `INFO` | plain | context only, jit makes no claim |

The `[critical]`/`[high]`/`[medium]`/`[low]` risk tags use the same ladder, so
a tag and a severity label of the same name are the same ink. `[clean]` is
green bold.

This ladder used to run red-bold / amber-bold / amber / cyan / white. On a
real terminal that is **three different yellows** — bold amber renders as
bright yellow, which most themes draw as orange — plus a cyan the palette
reserves for what the reader can type, plus a seventh ink. Encoding degree as
shades of one hue also breaks the rule the palette rests on: amber means
"needs a look", and it cannot also mean "needs a look, but more".

Amber now appears in exactly two weights tool-wide: **plain amber reports a
state** (the `○` glyph, `MEDIUM`, a percentage), **bold amber is a marker the
eye must find first** (the `!` on a findings item). Nothing else is yellow.

## Keep it short

A terminal line the reader has to track across 100 columns is a line they
skim, and jit's reports are read at the moment someone is deciding whether to
act. Length is a design constraint here, not a style preference.

- **One clause per line.** If a note needs "and" plus a subordinate clause, it
  is two facts — print the one that changes what the reader does and drop the
  other.
- **Aim for 72 characters** of natural length on any prose string, so it still
  fits after its indent on an 80-column window without wrapping. Wrapping is
  the safety net (`termtext.Wrap`), not the plan.
- **Variable-length content gets truncated, not wrapped**, so a row stays one
  row. Pick the cut by asking WHICH END CARRIES IDENTITY, not by the kind of
  value: `TruncMid` where both ends do (a path in a table whose rows share a
  long tail — two `okta-mcp-server/.env` manifests, one under `backup_2025/`,
  rendered identically under head-truncation on the screen asking you to
  approve rewriting them), `TruncTail` where the beginning does (the `→`
  action command: head-kept, because a wrapped command is neither readable nor
  copy-pasteable), `TruncHead` where only the tail does (a lone path, where
  the prefix is what every row repeats).
- **Explain once.** A fact that is true of every item in a group is stated on
  the group header, never repeated per line.
- The place this is hardest is the note under an action. Those earn their
  length only when they change the decision ("every change is reversible")
  — anything else is a sentence the reader pays for and doesn't use.

## The six rules

1. **One header shape: `[Name]  count`.** Every section, group, and dashboard
   label across jit is a bracketed name in default weight (not bold — the
   brackets delimit it, and they read better than bold), followed by a plain
   count where there's something to count. `[Exposed Secrets] 1`,
   `[custom_scripts-descope] 12`, `[vault]`, `● [Wired here]` — all the same
   motif, so the whole tool looks like one tool. Structure comes from this
   plus whitespace and weight, never box-rules; the only rule that stays is a
   single subtotal line under a numeric summary table (scan's category
   counts, migrate's plan total) — a table total is the one place a rule
   earns its keep.
2. **A glyph carries the state.** Every line that *has* a state leads with a
   colored mark, so status reads before prose:
   - `●` green — healthy / running / wired / serving real to a grant
   - `○` amber — needs a look / unreferenced / decoy
   - `✗` red — a real problem the reader must act on
   - `✓` green — an action completed (`✓ Scanned ...`)
3. **Hierarchy by weight.** Bold is the one primary thing on a line (a group
   name, a flagged path). Everything else — body text and everything secondary
   alike: counts, origins, timestamps, explanations — is plain, and recedes
   because the primary thing is bold, not because it was dimmed. Never reach
   for a color to mean "less important"; color here means state, and a
   secondary line that took one would be claiming a state it doesn't have.
4. **Align columns with space.** Like `docker ps`, values line up in
   whitespace columns with tabular figures, never box borders. Long lists of
   bare names flow into aligned columns (`flowNames`) instead of one item per
   line — a 14-secret group is three tidy rows, not a fourteen-line stack.
5. **Color means one thing.** Green = ok, amber = warn, red = risk, cyan = a
   path or command the reader can act on. No color is decorative, and the same
   fact never gets restated on every line — state a shared note (an origin, a
   decoy rule) once per group or section.

   **Cyan is the only color a command ever takes**, on every surface, always
   via `hlCmds`. This was drift for a while and it showed: `jit scan` painted
   its headline action green and its manual actions amber, `jit status` used
   cyan, and ~20 sites printed the backticks literally with no color at all —
   so the same sentence ("N kept for `jit migrate undo`") rendered three
   different ways depending on which command you typed. Green and amber report
   *state*; they belong on the glyph, the section header and the coverage
   arithmetic, never on the thing you type. An action line is a cyan `→`
   followed by default-weight prose, with cyan only on the runnable spans
   inside it — amber across the whole line made a sentence of plain advice
   ("rotate them now") read as a warning.

6. **Nothing is wider than the window.** A line printed at its natural length
   is not "unwrapped" — it is wrapped by the terminal, at column 0, which
   drops a continuation to the left of the glyph that owns it and turns one
   row into what reads as two. Every prose line goes through
   `termtext.Wrap` with the indent that keeps it under its own column, and
   every column budget comes from `termtext.Width()`. Paths that can't fit are
   cut deliberately, by which end carries identity — see the truncation rule
   above: `TruncMid` when both ends do, `TruncTail` when the head does,
   `TruncHead` when only the tail does.

## The three report shapes

One vocabulary, three layouts — each fits the shape of its data. What they
share is the palette, the glyphs, the plain-secondary rule, and column flow.

### Report — `jit scan`, `jit migrate`, `jit doctor`
A findings/plan list. A `[Category]` header in default weight with a plain
count — rule 1, same as everywhere else — then the items. (This section read
"Strong **bold** `[Category]`" until 2026-08-06, contradicting rule 1 above and
the code in both `internal/audit/report.go` and `internal/cli/migrateplan.go`,
which have always printed it plain.) A findings report should feel heavier than a status line, so
this is where a leading `✗` earns real weight. No rule under the header.

**`jit scan`'s default view carries no severity word at all**, and that is a
decision rather than an omission. The ladder above governs `--full`, the
markdown export and NDJSON; the triage view deliberately shows no scanner
vocabulary — no categories, no severity labels, no finding counts as headline
numbers — because it is the funnel, not the inventory. Severity still decides
the ORDER items appear in, so the ladder is doing its work without spending a
column on a word the reader cannot act on. The `!` is amber, or red when the
group is critical, and that is the whole severity signal in that view.

```
[.env Files] 13
  • ~/proj/.env
    HIGH  contains "JAMF_URL", a variable name that looks like a credential
```

`jit doctor` was filed under Dashboard here for a long time, and rendered as
neither: a flat list of `[kind] prose` lines with no headers, each indenting
its own continuation and action by its own label width, so one report had three
different left edges. It is a findings list — the same shape `jit scan`
carries — and `jit status` is the dashboard. Grouping by kind is what lets
rule 5 hold: twelve missing references used to repeat one remediation sentence
twelve times, and now state it once under the group that shares it.

```
[missing]  2
  ✗ profile "app" (project): DB_URL → db/url, not in the vault
  ✗ profile "app" (project): STRIPE_KEY → stripe/dev-key, not in the vault
  → jit vault set <path> for each, or jit migrate <path> to convert the files
```

A group's count is printed only when there is more than one to count — `[rekey] 1`
invites the reader to compare a number against nothing.

### Dashboard — `jit status`, `jit service status`
Aligned label/value rows. Each state-bearing row leads with a glyph so the one
that needs attention (`✗` broken, `○` unreferenced) is found at a glance. A
shared rule (mounts are decoy by default) is stated once in the header, not
per row.

**The glyph column is the summary — don't build a second one above it.** A
dashboard briefly opened with a verdict (`✗ 1 thing to fix`), on the theory
that the first line should answer "is there anything here for me?". It didn't:
a count names no finding, so the reader still had to scan down for the glyph it
meant, having first been told there was something to look for. A tally that
sends you looking is worse than no tally, and the glyphs already answer the
question on the row that owns it. Report state where it lives.

```
jit      0.66.0
secrets  65 stored in 15 groups
  ● Wired here          3 groups via 3 profiles (6 references), all resolve.
  ○ Unreferenced here   4 groups, 21 secrets. May belong to another project.
```

Counts are inflected, never `N thing(s)` — use `countWord`/`pluralWord` from
`format.go`. The `(s)` form reads as a form letter, and a report that says
"1 group(s)" has told the reader it isn't looking at their data.

### Tree — `jit vault list`, `jit status --secrets` groups
A nested namespace. Deliberately the **lightest** shape: no rules, no glyphs
on member rows, no per-item severity — across dozens of groups that weight
would bury the names it is supposed to present. The `[Name]` header from rule
1, a plain count, and members flowed into columns. A shared per-group note
(all members "no recorded origin") is stated once on the header.

This section used to say brackets were "far too heavy" here and showed a bare
bold name. That was written before rule 1, which chose one header motif for
the whole tool over a per-shape judgement, and the code followed rule 1. Read
across fifteen groups the brackets earn it: they delimit a name that can
itself contain dashes and dots (`npmrc-jitpass-playground`), which bold alone
does not.

```
[descope] 12
    DESCOPE_MGMT_KEY    DESCOPE_PROJECT_1   DESCOPE_PROJECT_2   DESCOPE_PROJECT_3
    DESCOPE_PROJECT_4   DESCOPE_PROJECT_5   DESCOPE_PROJECT_6   DESCOPE_PROJECT_7

[wiz] 5
    WIZ_API_ENDPOINT   WIZ_AUDIENCE   WIZ_AUTH_URL   WIZ_CLIENT_ID
    WIZ_CLIENT_SECRET
```

Under `jit status --secrets` the same groups sit beneath a state line, and the
shared note rides the header:

```
○ Unreferenced here  4 groups · 21 secrets · may belong to another project

  [custom_scripts-descope] 12 · no recorded origin
      DESCOPE_MGMT_KEY    DESCOPE_PROJECT_1   DESCOPE_PROJECT_2   DESCOPE_PROJECT_3
```

**Column flow is capped, and the cap is the point.** `flowNames` lays out to
at most `maxFlowWidth` (88) columns and `maxFlowCols` (4), whatever the
terminal offers. Rule 6 is a ceiling, not a target: flowed to the full width
of a 190-column window the same list became a six-or-more-column wall that
scanned worse than the stack it replaced. Column widths are per group, not
global — one 39-character name (`REGISTRY_INTERNAL_EXAMPLE_COM_AUTHTOKEN`)
would otherwise widen every column in the listing and drop the whole page to
two.

## The action line: `→ do this`

The one motif that crosses all three shapes. A state line says what **is**; the
line beneath it, led by a cyan `→`, says what to **do** about it — and nothing
else goes on that line. `jit scan` established it (`→ jit migrate` under a
coverage finding), and the dashboard follows: advice buried mid-sentence
("… the vault only decrypts on this Mac — run jit vault export <file>") reads
as prose the eye skims, while the same words on their own arrow line read as a
thing to go and type.

```
backup   ✗ no vault export on record — the vault only decrypts on this Mac
      → jit vault export <file> — a copy you could restore on another Mac
```

Rules: at most one arrow line per state (a reader given three next steps takes
none), commands in cyan via `hlCmds`, and any explanation goes **above** the
arrow as plain `printStatusNote` lines, never after it — the command is the
last thing on screen because it's the thing they act on.

An explanation line is plain and bare; a line carrying a **state of its own**
leads with a glyph instead (`printStatusWarnNote`). The distinction is load
bearing: a warning rendered glyphless directly under a green `●` row
gets read as part of that healthy row, which is how the build-mismatch notice
managed to hide in plain sight.

Say what the reader needs, not what the program knows. Build revisions, socket
paths and internal identifiers belong on the diagnostic surfaces (`jit doctor`,
`jit service status`) where someone is filing a bug — on a dashboard they
displace the words that would have explained the problem.

## Glyphs: why Unicode

jit already prints `✓` and `•`, and its darwin-only terminals (SF Mono /
Menlo) render `● ○ ✓ ✗` at single width. The `glyph*` constants in
`style.go` are the single place to swap for ASCII (`+ ! x -`) if a terminal
ever mis-widths them — nothing references the symbols directly.

## Coverage

Every list/report/dashboard surface is on the house style: `jit scan`,
`jit migrate` (plan + summary), `jit status` (dashboard + `--secrets`),
`jit vault list` / `jit vault orphans`, `jit service status`, `jit doctor`,
`jit audit`, `jit service log`, `jit guard history`, and the first-run flow.
When adding a new command, reach for the `style.go` helpers rather than raw
`color.New(...)` so it lands in the same style by default.

### The two logs

`jit audit` and `jit service log` were the last surfaces written for the
writer rather than the reader — one logfmt or timestamped line per event, each
repeating what the line above already said. Both now render the house style by
default and keep their original bytes one flag away: `jit audit --format
logfmt` and `jit service log --raw`.

That escape hatch is not a courtesy, it is the condition for reformatting a
log at all. Both views drop repeated prefixes, shorten paths, and fold runs of
identical events into one row with a `×N` count — which is what makes them
readable, and also exactly what would break a grep or a pasted bug report. A
line the formatter does not recognise (a panic, a stack frame) passes through
byte-exact: an unrecognised line in a debug log is precisely the one someone
is looking for, and reformatting it would be the view editing evidence it
does not understand.

Folding only ever collapses **adjacent, same-minute, same-outcome** events, so
a compressed display never reorders or thins the timeline.
