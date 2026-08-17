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
	migrateOpInventory = func() (opInventory, error) {
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
func (f *fakeOpIndex) Items() int { return f.items }

func TestOpLinkHookMatchesAndRecords(t *testing.T) {
	ix := &fakeOpIndex{
		entries: map[string]onepassword.IndexEntry{
			"sk_live_matching_value": {
				IDRef:   "op://vault-1/item-a/f1",
				NameRef: "op://Personal/Stripe/credential",
			},
		},
	}
	var linked []opLinkedRow
	var offered int
	hook := newOpLinkHook(ix, &linked, &offered)

	// A matching value links to the ID form and records the name form.
	ref, ok := hook("myapp/STRIPE_KEY", []byte("sk_live_matching_value"), vault.Meta{})
	if !ok || ref != "op://vault-1/item-a/f1" {
		t.Errorf("match returned (%q, %v), want the ID-form reference", ref, ok)
	}

	// A non-matching value declines.
	if _, ok := hook("myapp/OTHER", []byte("no-match-here"), vault.Meta{}); ok {
		t.Error("hook linked a value the index does not hold")
	}

	// A verbatim op:// value links as itself, no index consulted.
	ref, ok = hook("myapp/FROM_OP_RUN", []byte("op://Personal/GitHub/token"), vault.Meta{})
	if !ok || ref != "op://Personal/GitHub/token" {
		t.Errorf("verbatim reference returned (%q, %v), want itself", ref, ok)
	}

	if offered != 3 {
		t.Errorf("offered = %d, want every SetWithMeta counted", offered)
	}
	if len(linked) != 2 {
		t.Fatalf("linked rows = %d, want 2", len(linked))
	}
	if linked[0].ref != "op://Personal/Stripe/credential" {
		t.Errorf("recorded row ref = %q, want the NAME form for display", linked[0].ref)
	}
}

func TestOpLinkHookNilIndexStillLinksVerbatimRefs(t *testing.T) {
	var linked []opLinkedRow
	var offered int
	hook := newOpLinkHook(nil, &linked, &offered)

	if _, ok := hook("myapp/PLAIN", []byte("some-ordinary-value"), vault.Meta{}); ok {
		t.Error("nil index must never match a plain value")
	}
	ref, ok := hook("myapp/REF", []byte("op://Personal/X/field"), vault.Meta{})
	if !ok || ref != "op://Personal/X/field" {
		t.Errorf("verbatim link with nil index returned (%q, %v), want itself", ref, ok)
	}
}

func TestPrintOpLinkResultBlock(t *testing.T) {
	var buf bytes.Buffer
	printOpLinkResult(&buf, []opLinkedRow{
		{path: "myapp/DB_PASSWORD", ref: "op://Personal/Postgres/password"},
		{path: "myapp/STRIPE_KEY", ref: "op://Personal/Stripe/credential"},
	}, 12, 14, "")
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
}

func TestPrintOpLinkResultSkipNote(t *testing.T) {
	var buf bytes.Buffer
	printOpLinkResult(&buf, nil, 5, 0, "op item list failed: account is not signed in")
	out := buf.String()
	if !strings.Contains(out, "1Password check skipped") || !strings.Contains(out, "not signed in") {
		t.Errorf("expected the skip note carrying op's error, got:\n%s", out)
	}
	if !strings.Contains(out, "copied, not linked") {
		t.Errorf("the note must say what happened instead, got:\n%s", out)
	}
}

func TestPrintOpLinkResultSilentWhenNothingLinked(t *testing.T) {
	var buf bytes.Buffer
	printOpLinkResult(&buf, nil, 12, 14, "")
	if buf.Len() != 0 {
		t.Errorf("a run with no links must print nothing, got:\n%s", buf.String())
	}
}
