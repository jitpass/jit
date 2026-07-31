# jit output style

The house style every jit command shares, so the whole tool reads as one
tool. The instincts are borrowed from `gh` and `docker`: structure comes from
**whitespace and weight**, not box-rules; a leading **glyph** carries the
state so the eye finds it before the words; **color is strictly semantic**,
never decorative.

The shared vocabulary lives in `internal/cli/style.go`. Prefer those helpers
(`cDim`, `cBold`, `cPath`, `cOK`, `cWarn`, `cRisk`, the `glyph*` constants,
and `flowNames`) over hand-rolled `color.New(...)` calls so a future palette
change happens in exactly one place.

## The six rules

1. **One header shape: `[Name]  count`.** Every section, group, and dashboard
   label across jit is a bracketed name in default weight (not bold — the
   brackets delimit it, and they read better than bold), followed by a dim
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
   name, a flagged path). Body text is default weight. Everything secondary —
   counts, origins, timestamps, explanations — is dim. Never a third color to
   mean "less important"; that is what dim is for.
4. **Align columns with space.** Like `docker ps`, values line up in
   whitespace columns with tabular figures, never box borders. Long lists of
   bare names flow into aligned columns (`flowNames`) instead of one item per
   line — a 14-secret group is three tidy rows, not a fourteen-line stack.
5. **Color means one thing.** Green = ok, amber = warn, red = risk, cyan = a
   path or command the reader can act on. No color is decorative, and the same
   fact never gets restated on every line — state a shared note (an origin, a
   decoy rule) once per group or section, dimmed.

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
   cut deliberately: `TruncHead` for a path (the tail names the file),
   `TruncMid` for a command line whose two ends both carry identity,
   `TruncTail` where the beginning is what identifies it.

## The three report shapes

One vocabulary, three layouts — each fits the shape of its data. What they
share is the palette, the glyphs, the dim-secondary rule, and column flow.

### Report — `jit scan`, `jit migrate`
A findings/plan list. Strong **bold `[Category]`** header with a dim count,
then the items. A findings report should feel heavier than a status line, so
this is where a leading `✗` earns real weight. No rule under the header.

```
[.env Files] 13
  • ~/proj/.env
    HIGH  contains "JAMF_URL", a variable name that looks like a credential
```

### Dashboard — `jit status`, `jit service status`, `jit doctor`
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
1, a **dim** count, and members flowed into columns. A shared per-group note
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
arrow as dim `printStatusNote` lines, never after it — the command is the last
thing on screen because it's the thing they act on.

An explanation line is dim and bare; a line carrying a **state of its own**
leads with a glyph instead (`printStatusWarnNote`). The distinction is load
bearing: a warning rendered dim and glyphless directly under a green `●` row
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
`jit wrap doctor`, `jit audit`, `jit service log`, and the first-run flow.
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
