# Dry-run refactor: one frame, a complete plan, a scan that keeps its promises

**Status: implemented, 2026-08-17 (branch dryrun-frame, five commits —
one per phase). Preview rendering approved by eye 2026-08-17; this
document is the spec the implementation followed.**

`--dry-run` is the product's consent surface: the plan it prints is the
thing a real run's `[y/N]` commits to, byte for byte (GAPS.md #26). A
live dogfood run (bare `jit migrate --dry-run`, 2026-08-17) showed that
surface fraying in four ways at once, and a code sweep found the frame
was never owned by anyone. This refactor makes three guarantees:

1. **One frame.** Every dry-run prints exactly two `[DRY RUN]` markers:
   a banner as the first line, a trailer as the last. Nothing else
   carries a prefix, no lowercase `[dry-run]` variant exists anywhere.
2. **A complete plan.** Everything a real run will do appears as a plan
   row and is counted in the subtotal: file rewrites, CLI wraps (with
   kind-specific consequences, including the shell-rc PATH edit), the
   history guard, and the post-migrate agent-cache sweep.
3. **scan and migrate agree.** `jit scan` never counts a finding as
   "jit will protect these" that `jit migrate` will then refuse.

## What the dogfood run showed

- Three `[DRY RUN]` banners plus a stray lowercase `[dry-run] would
  wrap clisso` AFTER the "No files were changed" trailer. Cause: the
  banner/trailer live inside `applyMigrate`, but `runMigrateAll`
  prints wrap/guard disclosures before calling it and wrap lines after
  it returns. In a wraps-only run (`d.total()==0`) there is no banner
  and no trailer at all.
- The clisso wrap appeared in two prose paragraphs but never in the
  plan body; "2 changes planned across 2 categories" excluded it.
- `jit scan` promised `Secret.yaml` under "jit will protect these"
  (+3%); migrate then skipped it as complex (mixed
  `data:`/`stringData:`). `remedy.go` gives every ConfidenceHigh k8s
  manifest `RemedyMigrate` without running migrate's classifier.
- A real run rewrites files the plan never listed: the agent-cache
  sweep (`CleanAgentCaches`) redacts copies of just-vaulted values,
  and `ensureShimOnPath` appends a PATH line to the shell rc. Neither
  was previewed. `jit wrap <tool>` has no `--dry-run` at all.

## Decisions

**D1. The command runner owns the frame, not `applyMigrate`.**
Two helpers, `printDryRunBanner(out)` and
`printDryRunTrailer(out, applyCmd, hint)`, are called by each runner
(`runMigratePath`, `runMigrateAll`, `migrate undo`, `migrate caches`)
as the first and last output of a dry run. `applyMigrate` stops
printing either; its dry-run early-return (before the confirm, before
`openVault`) is unchanged. This closes the wraps-only no-frame hole by
construction.

**D2. Banner text unchanged; trailer slimmed.** The banner keeps its
reported-bug rationale (GAPS.md #32) verbatim. The trailer stops
restating "changes nothing" and carries only what the banner cannot:
the apply command and the scope hint.

    [DRY RUN] Apply this plan: <the user's own argv, minus --dry-run>
    This only covers what jit migrate can act on; run jit scan for the
    complete picture, including findings it can never auto-fix, like
    private keys.

The apply command echoes the real invocation (path args, `--only`,
`--mount` preserved), so it is always copy-pasteable. `undo` and
`caches` pass their own apply command and no scan hint.

**D3. Wraps and the guard become plan categories.** Rendered inside
`printMigratePlan`, counted in the subtotal, for both `--dry-run` and
the real confirm, so parity holds by construction. The pre-plan prose
paragraphs and the post-trailer `[dry-run] would ...` duplicates are
deleted; the plan row IS the consent line. `printMigratePlan` takes a
new `planExtras` struct (wrap rows, guard offer, cache preview)
alongside `discovered`; `runMigratePath` passes an empty one.

Wrap rows state the kind-specific consequence, sourced from the
compiled-in catalog (no prompts, no network):

- `KindShim`: token discovered from the tool's config moves to the
  vault; the config is scrubbed (backed up encrypted first).
- `KindCapture` (clisso): shim reroutes each mint into the vault; the
  long-lived client-secret in the tool's config moves to the vault.
- `KindNative`: delegates to the named native-helper migrate flow.
- `KindRunGrant`: shim only; the k8s migration owns the vaulting.

Every wrap row that would install a first shim also discloses the rc
edit: "adds the shim PATH line to ~/.zshrc if missing". Detail lines
use the `└` evidence glyph per `design/output-style.md`.

**D4. The agent-cache sweep is previewed as a plan category.** The
sweep's needles are plaintext values sitting in the files being
migrated, readable at plan time without the vault. The plan parses
them with the existing per-category previews and calls
`migrate.PreviewAgentCaches` to render an `[AI agent caches]` category
with the real files, counted in the subtotal. Best-effort: a preview
error degrades to one note line ("agent caches are swept after
vaulting; preview unavailable: <err>") and never blocks the plan.
The real run keeps computing needles from `v.OnSet` as today; the
preview is disclosure, not the apply path.

**D5. scan asks migrate about k8s manifests.** `audit.Config` gains
`K8sMigratable func(path) (reason string, ok bool)` (the
`vault.KeyWrapper` pattern; audit cannot import migrate). cli wires it
to `migrate.ClassifyK8sSecretManifest`. A refused manifest flips to
`RemedyManual` with the refusal reason as its evidence line, moving it
to "only you can fix" and out of the percent promise. Nil hook (tests,
other callers) keeps today's behavior.

**D6. `--dry-run` is promoted to the wrap and guard surfaces.**
`jit wrap <tool> --dry-run`, `jit wrap undo <tool> --dry-run`, and
`jit guard history --dry-run` reuse the same plan-row renderers and
the same frame helpers. One dry-run vocabulary across the CLI. Native
wraps preview the delegated command instead of running it.

**D7. Catalog-owned config files route to their wrap.** A named path
that a catalog tool owns (e.g. `~/.clisso.yaml`) no longer falls
through to the loose-secret "mixes a secret with other content" skip;
its skip hint names the real fix: `jit wrap clisso`.

**D8. Style sweep.** `printSkippedFindings` hints go through
`wrapBody`; skipped paths are middle-truncated with the same helper
scan uses; the 1Password notice and the wrap disclosure lose their
hand-placed line breaks; bare-run group headers say "flagged by the
scan" instead of "you named" (targeted runs keep "you named");
`migratecaches`' lowercase `[dry-run]` marker is deleted with the
rest.

## Invariants preserved (do not regress)

- GAPS.md #26: `--dry-run` preview and the real confirm plan are the
  same rendering; the parity test extends to the new categories.
- GAPS.md #17: the confirm (and the dry-run early-return) precede
  `openVault`; declining or previewing never costs a Touch ID prompt.
- GAPS.md #32: the banner precedes the plan.
- The plan never prompts: no `op` contact (PATH probe only), no vault
  open, no agent contact. The cache preview reads files only.
- `jit scan` stays strictly read-only in every mode (D5 adds a parse,
  not a write).

## Phases

1. **Frame** (D1, D2): helpers in `migrate.go`; runners own
   banner/trailer; `undo.go`, `migratecaches.go` adopt them; delete
   the stray tail prints. Test: exactly two `[DRY RUN]` markers per
   run, including the wraps-only run.
2. **Plan completeness** (D3, D4): `planExtras`, wrap/guard/cache
   categories, subtotal counts them; delete prose disclosures.
3. **Wrap/guard dry-run** (D6) and skip-hint routing (D7).
4. **scan coherence** (D5): the hook, remedy flip, evidence line.
5. **Style** (D8) and the full gate: parity test update,
   `migrate1password_test`, undo/caches tests, new wraps-only-frame
   and k8s-remedy-flip tests; `go run ./cmd/jit docs-gen` for the new
   flags; gofmt/vet/staticcheck/govulncheck/gosec.

## Out of scope

- Previewing which values 1Password will link: requires `op`'s auth
  prompt, and the plan must stay prompt-free. The notice line is the
  honest ceiling.
- Any change to what migrate refuses (complex tfvars/k8s, mixed
  loose files): this work makes refusals visible earlier, not fewer.
