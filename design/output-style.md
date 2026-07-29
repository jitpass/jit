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

## The five rules

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
A nested namespace. Deliberately the **lightest** shape — bracket headers and
rules would be far too heavy across dozens of groups. A **bold** group name, a
**dim** count, and members flowed into columns. A shared per-group note (all
members "no recorded origin") is stated once on the header.

```
○ Unreferenced here  4 groups · 21 secrets · may belong to another project

  custom_scripts-descope 12 · no recorded origin
      DESCOPE_MGMT_KEY    DESCOPE_PROJECT_1   DESCOPE_PROJECT_2   DESCOPE_PROJECT_3
      DESCOPE_PROJECT_4   DESCOPE_PROJECT_5   DESCOPE_PROJECT_6   DESCOPE_PROJECT_7
```

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
`jit wrap doctor`, and the first-run flow. When adding a new command, reach
for the `style.go` helpers rather than raw `color.New(...)` so it lands in
the same style by default.
