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

1. **Whitespace over box-rules.** A bold header plus a blank line separates
   sections as clearly as a `─────` underline, with far less ink. The only
   rule that stays is a single subtotal line under a numeric summary table
   (scan's category counts, migrate's plan total) — a table total is the one
   place a rule earns its keep.
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

```
Secrets: 65 stored in 15 group(s).
  ● Wired here:        3 group(s) via 3 profile(s) (6 reference(s)), all resolve.
  ○ Unreferenced here: 4 group(s), 21 secret(s). May belong to another project.
```

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

## Glyphs: why Unicode

jit already prints `✓` and `•`, and its darwin-only terminals (SF Mono /
Menlo) render `● ○ ✓ ✗` at single width. The `glyph*` constants in
`style.go` are the single place to swap for ASCII (`+ ! x -`) if a terminal
ever mis-widths them — nothing references the symbols directly.

## Not yet converted

Tracked so the next pass knows where to look, not a claim they're broken:

- `jit vault list`'s tree could flow its members into columns the way
  `jit status --secrets` now does.
- `jit doctor`, `jit wrap` catalog, and the first-run flow predate this style.
