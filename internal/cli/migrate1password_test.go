// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/onepassword"
	"github.com/jitpass/jit/internal/ui"
	"github.com/jitpass/jit/internal/vault"
)

// TestMain pins the 1Password seams OFF for the whole package: without
// this, every migrate test's output would depend on whether the machine
// running it happens to have `op` installed, and a future test that
// reaches the post-confirm dedupe would exec the real CLI and block on
// 1Password's authorization dialog. Tests that want the feature flip the
// vars themselves and restore them.
func TestMain(m *testing.M) {
	migrateOpInstalled = func() bool { return false }
	migrateOpInventory = func(func(read, listed int)) (opInventory, error) {
		return nil, errors.New("1Password inventory pinned off in tests")
	}
	doctorOpVerified = func() (string, error) { return "", errors.New("op pinned off in tests") }
	doctorOpVersion = func(string) string { return "" }
	os.Exit(m.Run())
}

// withOpInstalled pins the cheap PATH probe for one test.
func withOpInstalled(t *testing.T, installed bool) {
	t.Helper()
	prev := migrateOpInstalled
	migrateOpInstalled = func() bool { return installed }
	t.Cleanup(func() { migrateOpInstalled = prev })
}

func writePlanEnvFixture(t *testing.T, home string) string {
	t.Helper()
	target := filepath.Join(home, "proj", ".env")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(target, []byte("STRIPE_KEY=sk_test_fixture\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return target
}

// The plan's announcement line keys off the PATH probe alone — never an
// exec, never a prompt — and prints in --dry-run and the real plan alike
// (same rendering path). --no-1password silences it: an announcement for
// a dedupe the user just disabled would be noise.
func TestMigratePlanAnnounces1Password(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	target := writePlanEnvFixture(t, home)

	withOpInstalled(t, true)
	out, err := execMigrate(t, target, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate --dry-run: %v", err)
	}
	if !strings.Contains(out, "1Password CLI detected") {
		t.Errorf("expected the 1Password announcement with op installed, got:\n%s", out)
	}

	out, err = execMigrate(t, target, "--dry-run", "--no-1password")
	if err != nil {
		t.Fatalf("jit migrate --dry-run --no-1password: %v", err)
	}
	if strings.Contains(out, "1Password CLI detected") {
		t.Errorf("--no-1password must silence the announcement, got:\n%s", out)
	}
}

func TestMigratePlanSilentWithoutOp(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	target := writePlanEnvFixture(t, home)

	withOpInstalled(t, false)
	out, err := execMigrate(t, target, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate --dry-run: %v", err)
	}
	if strings.Contains(out, "1Password") {
		t.Errorf("no op on PATH must mean no 1Password mention anywhere in the plan, got:\n%s", out)
	}
}

// fakeOpIndex is a test opInventory: a value→entry table.
type fakeOpIndex struct {
	entries map[string]onepassword.IndexEntry
	items   int
}

func (f *fakeOpIndex) RefFor(value []byte) (onepassword.IndexEntry, bool) {
	e, ok := f.entries[string(value)]
	return e, ok
}
func (f *fakeOpIndex) Items() int         { return f.items }
func (f *fakeOpIndex) Listed() int        { return f.items }
func (f *fakeOpIndex) Incomplete() string { return "" }

// withOpInventory pins the enumeration for one test to return ix (or err),
// and counts how many times it ran — the laziness assertions live on that
// count. progressTicks, when non-nil, receives what a real enumeration
// would report so the tracker wiring can be observed.
func withOpInventory(t *testing.T, ix opInventory, err error) *int {
	t.Helper()
	runs := 0
	prev := migrateOpInventory
	migrateOpInventory = func(progress func(read, listed int)) (opInventory, error) {
		runs++
		if progress != nil && ix != nil {
			progress(ix.Items(), ix.Listed())
		}
		return ix, err
	}
	t.Cleanup(func() { migrateOpInventory = prev })
	return &runs
}

func TestOpLinkHookMatchesAndRecords(t *testing.T) {
	ix := &fakeOpIndex{
		items: 14,
		entries: map[string]onepassword.IndexEntry{
			"sk_live_matching_value": {
				IDRef:   "op://vault-1/item-a/f1",
				NameRef: "op://Personal/Stripe/credential",
			},
		},
	}
	runs := withOpInventory(t, ix, nil)
	d := newOpDedupe(nil)

	// A matching value links to the ID form and records the name form.
	ref, ok := d.hook("myapp/STRIPE_KEY", []byte("sk_live_matching_value"), vault.Meta{})
	if !ok || ref != "op://vault-1/item-a/f1" {
		t.Errorf("match returned (%q, %v), want the ID-form reference", ref, ok)
	}

	// A non-matching value declines.
	if _, ok := d.hook("myapp/OTHER", []byte("no-match-here"), vault.Meta{}); ok {
		t.Error("hook linked a value the index does not hold")
	}

	// A verbatim op:// value links as itself, no index consulted.
	ref, ok = d.hook("myapp/FROM_OP_RUN", []byte("op://Personal/GitHub/token"), vault.Meta{})
	if !ok || ref != "op://Personal/GitHub/token" {
		t.Errorf("verbatim reference returned (%q, %v), want itself", ref, ok)
	}

	if d.offered != 3 {
		t.Errorf("offered = %d, want every SetWithMeta counted", d.offered)
	}
	if len(d.linked) != 2 {
		t.Fatalf("linked rows = %d, want 2", len(d.linked))
	}
	if d.linked[0].ref != "op://Personal/Stripe/credential" {
		t.Errorf("recorded row ref = %q, want the NAME form for display", d.linked[0].ref)
	}
	if *runs != 1 {
		t.Errorf("enumeration ran %d times, want exactly once for the whole run", *runs)
	}
	if !d.stats.ran || d.stats.read != 14 {
		t.Errorf("stats = %+v, want ran with 14 items read", d.stats)
	}
}

// The enumeration is the expensive part — a prompt and one op call per
// item — so it must not run for a value that could never link: one under
// the match floor, or one that already is a reference.
func TestOpLinkHookIsLazy(t *testing.T) {
	runs := withOpInventory(t, &fakeOpIndex{items: 3}, nil)
	d := newOpDedupe(nil)

	if _, ok := d.hook("myapp/PIN", []byte("admin"), vault.Meta{}); ok {
		t.Error("a value under the floor linked")
	}
	ref, ok := d.hook("myapp/REF", []byte("op://Personal/X/field"), vault.Meta{})
	if !ok || ref != "op://Personal/X/field" {
		t.Errorf("verbatim link returned (%q, %v), want itself", ref, ok)
	}
	if *runs != 0 {
		t.Fatalf("enumeration ran %d times for values that could never match, want 0", *runs)
	}
	if d.stats.ran {
		t.Error("stats claim the check ran; the mutation log would report a check that never happened")
	}

	// The first linkable candidate triggers it, once.
	d.hook("myapp/A", []byte("long-enough-candidate"), vault.Meta{})
	d.hook("myapp/B", []byte("another-long-candidate"), vault.Meta{})
	if *runs != 1 {
		t.Errorf("enumeration ran %d times, want once", *runs)
	}
}

func TestOpLinkHookFailedEnumerationStillLinksVerbatimRefs(t *testing.T) {
	withOpInventory(t, nil, errors.New("op item list failed: account is not signed in"))
	d := newOpDedupe(nil)

	if _, ok := d.hook("myapp/PLAIN", []byte("some-ordinary-value"), vault.Meta{}); ok {
		t.Error("a failed enumeration must never match a plain value")
	}
	if d.skipNote == "" || !strings.Contains(d.skipNote, "not signed in") {
		t.Errorf("skipNote = %q, want op's own error for the mutation log", d.skipNote)
	}
	ref, ok := d.hook("myapp/REF", []byte("op://Personal/X/field"), vault.Meta{})
	if !ok || ref != "op://Personal/X/field" {
		t.Errorf("verbatim link after a failed enumeration returned (%q, %v), want itself", ref, ok)
	}
}

// The tracker step is what stands between the user and a minutes-long
// silence: it must start before the enumeration and be stopped (settled,
// so nothing can interleave with stdout) before the hook returns.
func TestOpLinkHookAnimatesTheEnumeration(t *testing.T) {
	withOpInventory(t, &fakeOpIndex{items: 174}, nil)
	var trail bytes.Buffer
	d := newOpDedupe(func() *ui.Tracker { return ui.New(&trail, true, false) })
	d.hook("myapp/A", []byte("long-enough-candidate"), vault.Meta{})
	if !strings.Contains(trail.String(), "checking 1Password") {
		t.Errorf("no progress line while enumerating, got:\n%s", trail.String())
	}
}

func TestPrintOpLinkResultBlock(t *testing.T) {
	var buf bytes.Buffer
	printOpLinkResult(&buf, []opLinkedRow{
		{path: "myapp/DB_PASSWORD", ref: "op://Personal/Postgres/password"},
		{path: "myapp/STRIPE_KEY", ref: "op://Personal/Stripe/credential"},
	}, 12, opCheckStats{ran: true, read: 14, listed: 14}, "")
	out := buf.String()
	for _, want := range []string{
		"[1Password] 2 of 12 linked, not copied · 14 items checked",
		"myapp/DB_PASSWORD",
		"op://Personal/Stripe/credential",
		"Rotate these in 1Password",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the block, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "stopped early") || strings.Contains(out, "No migrated value") {
		t.Errorf("a complete, matching run printed a shortfall or no-match line:\n%s", out)
	}
}

func TestPrintOpLinkResultSkipNote(t *testing.T) {
	var buf bytes.Buffer
	printOpLinkResult(&buf, nil, 5, opCheckStats{ran: true}, "op item list failed: account is not signed in")
	out := buf.String()
	if !strings.Contains(out, "1Password check skipped") || !strings.Contains(out, "not signed in") {
		t.Errorf("expected the skip note carrying op's error, got:\n%s", out)
	}
	if !strings.Contains(out, "copied, not linked") {
		t.Errorf("the note must say what happened instead, got:\n%s", out)
	}
}

// op never consulted (every value under the floor, or verbatim): there is
// no 1Password outcome, so nothing prints.
func TestPrintOpLinkResultSilentWhenNeverConsulted(t *testing.T) {
	var buf bytes.Buffer
	printOpLinkResult(&buf, nil, 12, opCheckStats{}, "")
	if buf.Len() != 0 {
		t.Errorf("a run that never consulted op must print nothing, got:\n%s", buf.String())
	}
}

// The check ran — the user waited through it, maybe answered a prompt —
// and nothing matched: say so, with the counts, instead of silence.
func TestPrintOpLinkResultNothingMatchedSaysSo(t *testing.T) {
	var buf bytes.Buffer
	printOpLinkResult(&buf, nil, 12, opCheckStats{ran: true, read: 174, listed: 174}, "")
	out := buf.String()
	for _, want := range []string{
		"[1Password] 0 of 12 linked, not copied · 174 items checked",
		"No migrated value matched a concealed 1Password field.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Rotate these") {
		t.Errorf("the rotate advice printed with nothing linked:\n%s", out)
	}
}

func TestPrintOpLinkResultShortfallIsStated(t *testing.T) {
	var buf bytes.Buffer
	printOpLinkResult(&buf, []opLinkedRow{{path: "myapp/DB_PASSWORD", ref: "op://Personal/Postgres/password"}},
		12, opCheckStats{ran: true, read: 150, listed: 174, incomplete: "[ERROR] 2026/09/05 rate limit exceeded"}, "")
	out := buf.String()
	for _, want := range []string{
		"1 of 12 linked, not copied · 150 of 174 items read",
		"op stopped early: [ERROR] 2026/09/05 rate limit exceeded",
		"myapp/DB_PASSWORD",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q, got:\n%s", want, out)
		}
	}
}
