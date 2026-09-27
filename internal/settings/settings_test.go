// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package settings

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

func TestPointerRoundTrip(t *testing.T) {
	p := Pointer("billing-sync/BILLING_URL")
	if p != "jit://setting/billing-sync/BILLING_URL" {
		t.Errorf("Pointer = %q", p)
	}
	if got, ok := PathOf(p); !ok || got != "billing-sync/BILLING_URL" {
		t.Errorf("PathOf(%q) = %q, %v", p, got, ok)
	}
	// A vault path is not a pointer, and no pointer is a legal vault path.
	if IsPointer("billing-sync/BILLING_CLIENT_SECRET") {
		t.Error("a vault path read as a setting pointer")
	}
	if err := vault.ValidatePath(p); err == nil {
		t.Errorf("vault.ValidatePath(%q) accepted a setting pointer", p)
	}
}

func TestStoreSetGetRemove(t *testing.T) {
	root := t.TempDir()
	s := New(root)
	const path = "billing-sync/BILLING_URL"

	if ok, err := s.Exists(path); err != nil || ok {
		t.Fatalf("Exists before Set = %v, %v", ok, err)
	}
	if _, err := s.Get(path); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get before Set = %v, want ErrNotFound", err)
	}
	if err := s.Set(path, []byte("https://billing.example.com")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(path)
	if err != nil || string(got) != "https://billing.example.com" {
		t.Fatalf("Get = %q, %v", got, err)
	}

	// As private as the .env the value came from.
	f := filepath.Join(root, Dir, "billing-sync", "BILLING_URL")
	info, err := os.Stat(f)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("setting file mode = %o, want 600", perm)
	}
	dir, err := os.Stat(filepath.Dir(f))
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if perm := dir.Mode().Perm(); perm != 0o700 {
		t.Errorf("settings folder mode = %o, want 700", perm)
	}

	if err := s.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if ok, _ := s.Exists(path); ok {
		t.Error("setting still there after Remove")
	}
	if err := s.Remove(path); err != nil {
		t.Errorf("Remove of a missing setting = %v, want nil", err)
	}
}

func TestStoreRefusesPathsOutsideIt(t *testing.T) {
	s := New(t.TempDir())
	for _, p := range []string{"", "../escape", "a/../../b", "/abs", "a//b", "a/./b", "sp ace"} {
		if err := s.Set(p, []byte("x")); err == nil {
			t.Errorf("Set(%q) succeeded, want refused", p)
		}
	}
}

// The grammar is repeated from internal/vault (this package must not import
// it). The two must accept the same paths, or a setting could be written at
// a path the vault would refuse, and moving it in would fail.
func TestPathPatternMatchesVault(t *testing.T) {
	for _, p := range []string{
		"a", "billing-sync/BILLING_URL", "a.b/c_d-e", "db..old/key", "x/y/z",
		"", "../x", "a/..", "a/.", "/a", "a/", "a//b", "a b", "a:b", "jit://setting/a",
	} {
		mine, theirs := ValidatePath(p) == nil, vault.ValidatePath(p) == nil
		if mine != theirs {
			t.Errorf("path %q: settings accepts=%v, vault accepts=%v", p, mine, theirs)
		}
	}
}
