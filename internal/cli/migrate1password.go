// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"

	"github.com/jitpass/jit/internal/onepassword"
	"github.com/jitpass/jit/internal/termtext"
	"github.com/jitpass/jit/internal/ui"
	"github.com/jitpass/jit/internal/vault"
)

// This file is migrate's 1Password dedupe (design/1password-adapter.md):
// a value about to be vaulted that already lives in 1Password is stored
// as a reference to it, not a copy. The enumeration behind it is the
// expensive part — one authorization prompt and one `op item get` per
// credential item in the account — so it runs LAZILY, on the first value
// that could possibly link: a run whose every value is under the match
// floor, or already an op:// reference, never contacts op at all. The
// plan's announcement line stays a PATH probe (a plan must never prompt),
// and the result prints as a `[1Password]` block in the mutation log.

// opInventory is what the dedupe needs from onepassword.Index, as an
// interface so tests can pin a fake index without a real `op`.
type opInventory interface {
	RefFor(value []byte) (onepassword.IndexEntry, bool)
	Items() int
	Listed() int
	Incomplete() string
}

// migrateOpInstalled/migrateOpInventory are the 1Password seams: the
// plan's announcement line keys off the cheap PATH probe, the post-confirm
// dedupe off the real enumeration. Vars so tests pin both — the plan must
// render identically on machines with and without op installed.
var (
	migrateOpInstalled = onepassword.Installed
	migrateOpInventory = func(progress func(read, listed int)) (opInventory, error) {
		ix, err := onepassword.New().Inventory(progress)
		if err != nil {
			return nil, err
		}
		return ix, nil
	}
)

type opLinkedRow struct{ path, ref string }

// opCheckStats is what the mutation log says about the enumeration once
// it has run: how many items op was asked for, how many it answered, and
// its own error line if it stopped early.
type opCheckStats struct {
	ran          bool
	read, listed int
	incomplete   string
}

// opDedupe owns one migrate run's 1Password state: the lazily built
// index, the rows it linked, and the tally the mutation log reports. Its
// hook is the vault.LinkOnSet migrate installs.
type opDedupe struct {
	newTracker func() *ui.Tracker

	once     bool
	ix       opInventory
	skipNote string
	stats    opCheckStats
	linked   []opLinkedRow
	offered  int
}

// newOpDedupe builds the dedupe for a run that vaults values with op on
// PATH and --no-1password unset. newTracker supplies the stderr progress
// line the enumeration animates while it waits (nil for none).
func newOpDedupe(newTracker func() *ui.Tracker) *opDedupe {
	if newTracker == nil {
		newTracker = func() *ui.Tracker { return ui.New(io.Discard, false, false) }
	}
	return &opDedupe{newTracker: newTracker}
}

// hook is the vault.LinkOnSet: a value that already IS an op:// reference
// links as itself (a .env kept for `op run` needs no index, and vaulting
// the literal would hand `jit run` an unresolvable string); a value under
// the match floor can never link and costs nothing; anything else builds
// the index on first use and links iff its bytes match a concealed
// 1Password field. The stored reference is the rename-proof ID form; the
// recorded row carries the name form for the mutation log.
func (d *opDedupe) hook(path string, value []byte, _ vault.Meta) (string, bool) {
	d.offered++
	if s := string(value); onepassword.ValidateRef(s) == nil {
		d.linked = append(d.linked, opLinkedRow{path: path, ref: s})
		return s, true
	}
	if len(value) < onepassword.MinLinkableValueLen {
		return "", false
	}
	d.ensure()
	if d.ix == nil {
		return "", false
	}
	e, ok := d.ix.RefFor(value)
	if !ok {
		return "", false
	}
	d.linked = append(d.linked, opLinkedRow{path: path, ref: e.NameRef})
	return e.IDRef, true
}

// ensure runs the enumeration once, behind a spinner that counts items as
// they stream in, so minutes of `op item get` never look like a hang. A
// failed enumeration (signed-out CLI, locked app, a fake op the signature
// gate rejected) fails open: the run continues on copies and the mutation
// log says so once. The hook stays installed either way — verbatim op://
// values need no index.
func (d *opDedupe) ensure() {
	if d.once {
		return
	}
	d.once = true
	d.stats.ran = true

	tr := d.newTracker()
	tr.Collapse()
	tr.Step("checking 1Password for already-stored values (its prompt may appear)", "")
	ix, err := migrateOpInventory(func(read, listed int) {
		tr.Update(fmt.Sprintf("%d/%d items", read, listed))
	})
	if err != nil {
		tr.Stop()
		d.skipNote = err.Error()
		return
	}
	d.ix = ix
	d.stats.read, d.stats.listed, d.stats.incomplete = ix.Items(), ix.Listed(), ix.Incomplete()
	tr.StopCollapsed("checked 1Password: " + countWord(ix.Items(), "item", "items"))
}

// print renders the run's 1Password outcome after the per-category
// results. Nil-safe: a run that never installed the dedupe prints
// nothing.
func (d *opDedupe) print(w io.Writer) {
	if d == nil {
		return
	}
	printOpLinkResult(w, d.linked, d.offered, d.stats, d.skipNote)
}

// printOpLinkResult renders the 1Password dedupe outcome. Four cases: the
// check failed (one amber note — the run continued with copies, fail
// open); op was never consulted (silence: every value was under the
// floor or a verbatim reference, and there is no 1Password outcome to
// report); the check ran and nothing matched (the header with its
// counts, so a user who just waited through the enumeration — and
// possibly answered 1Password's prompt — sees that it ran, what it
// covered, and that copies were the honest result); or N linked (the
// block naming each path → reference, so the user knows exactly which
// secrets now follow 1Password rotation). A shortfall — op stopped
// answering before every listed item — is stated on the header and
// explained with op's own line, never hidden inside a rounder number.
func printOpLinkResult(w io.Writer, linked []opLinkedRow, offered int, stats opCheckStats, skipNote string) {
	if skipNote != "" {
		_, _ = cWarn.Fprint(w, glyphWarn)
		wrapBody(w, 1, "  ", " 1Password check skipped: "+skipNote+"; values were copied, not linked")
		fmt.Fprintln(w)
		return
	}
	if !stats.ran {
		return
	}
	items := countWord(stats.read, "item", "items") + " checked"
	if stats.read < stats.listed {
		items = fmt.Sprintf("%d of %d items read", stats.read, stats.listed)
	}
	printMigrateResultCategoryLabel(w, fmt.Sprintf("%d of %d linked, not copied · %s", len(linked), offered, items))
	if stats.incomplete != "" {
		fmt.Fprintln(w, truncateEnd("  op stopped early: "+stats.incomplete, termtext.Width()))
	}
	if len(linked) == 0 {
		fmt.Fprintln(w, "  No migrated value matched a concealed 1Password field.")
		fmt.Fprintln(w)
		return
	}
	widest := 0
	for _, r := range linked {
		if len(r.path) > widest {
			widest = len(r.path)
		}
	}
	for _, r := range linked {
		// Truncate the variable tail rather than wrap: one row per secret.
		row := fmt.Sprintf("  %-*s %s %s", widest, r.path, glyphAction, r.ref)
		fmt.Fprintln(w, truncateEnd(row, termtext.Width()))
	}
	fmt.Fprintln(w, "  Rotate these in 1Password; jit follows. The vault holds the")
	fmt.Fprintln(w, "  reference, never a copy.")
	fmt.Fprintln(w)
}

// printMigrateResultCategoryLabel is printMigrateResultCategory for a
// header whose tail is richer than a bare count.
func printMigrateResultCategoryLabel(w io.Writer, tail string) {
	fmt.Fprintf(w, "[1Password] %s\n", tail)
}
