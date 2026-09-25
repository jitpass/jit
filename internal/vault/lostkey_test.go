// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func plantSealedKey(t *testing.T, root, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, SealedKeyFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setSecrets(t *testing.T, v *Vault, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := v.Set(p, []byte("value of "+p)); err != nil {
			t.Fatal(err)
		}
	}
}

func sealedToLost(t *testing.T, root string) []string {
	t.Helper()
	got, known, err := SealedToLostKey(root)
	if err != nil || !known {
		t.Fatalf("SealedToLostKey: known=%v err=%v", known, err)
	}
	return got
}

// The whole point: after the lost key is set aside, exactly the envelopes
// still sealed to it are reported, however the vault changes afterwards,
// and reading them never needs a key (the Vault here has none).
func TestSealedToLostKeyTracksWhatTheNewKeyCannotOpen(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "aws/key", "stripe/key", "github/token")
	if got := sealedToLost(t, v.Root); got != nil {
		t.Fatalf("no key set aside yet, got %q", got)
	}
	plantSealedKey(t, v.Root, "sealed-to-the-old-key")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(v.Root, SealedKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("the sealed key file is still in place: %v", err)
	}
	if got, want := sealedToLost(t, v.Root), []string{"aws/key", "github/token", "stripe/key"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("right after set-aside: %q, want %q", got, want)
	}

	// A restore rewrites a path (fresh DEK, different bytes); a removal
	// takes one away; a new secret was never the old key's.
	setSecrets(t, v, "aws/key", "new/secret")
	if err := v.Remove("stripe/key"); err != nil {
		t.Fatal(err)
	}
	if got, want := sealedToLost(t, v.Root), []string{"github/token"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after a partial restore: %q, want %q", got, want)
	}
}

// A restore that leaves secrets behind settles nothing: the lost key's
// file stays, so the state stays reported, and what was left is named.
// Once nothing is left the file is retired, renamed and never deleted.
func TestSettleLostKeyKeepsTheStateUntilNothingIsLeft(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a", "b")
	plantSealedKey(t, v.Root, "sealed-to-the-old-key")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	setSecrets(t, v, "a")

	remaining, unknown, err := SettleLostKey(v.Root, time.Now())
	if err != nil || unknown || !reflect.DeepEqual(remaining, []string{"b"}) {
		t.Fatalf("partial restore: remaining=%q unknown=%v err=%v, want [b]", remaining, unknown, err)
	}
	if _, err := os.Stat(filepath.Join(v.Root, LostSealedKeyFile)); err != nil {
		t.Fatalf("a partial restore retired the lost key's file: %v", err)
	}

	setSecrets(t, v, "b")
	remaining, unknown, err = SettleLostKey(v.Root, time.Now())
	if err != nil || unknown || remaining != nil {
		t.Fatalf("full restore: remaining=%q unknown=%v err=%v", remaining, unknown, err)
	}
	if got := sealedToLost(t, v.Root); got != nil {
		t.Fatalf("after a full restore still reported: %q", got)
	}
	retired, _ := filepath.Glob(filepath.Join(v.Root, LostSealedKeyFile+"-*"))
	var kept []string
	for _, f := range retired {
		if data, err := os.ReadFile(f); err == nil && string(data) == "sealed-to-the-old-key" {
			kept = append(kept, f)
		}
	}
	if len(kept) != 1 {
		t.Fatalf("the lost key's sealed file was not kept under a retired name: %q", retired)
	}
}

// A second loss before the first was settled must not overwrite the first
// one's sealed file: it is the only thing that could open those secrets.
func TestSetAsideKeepsAnEarlierLostKey(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a")
	plantSealedKey(t, v.Root, "first")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	plantSealedKey(t, v.Root, "second")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	contents := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(v.Root, LostSealedKeyFile+"*"))
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil {
			contents[string(data)] = true
		}
	}
	if !contents["first"] || !contents["second"] {
		t.Fatalf("after two losses the kept sealed files hold %v, want both", contents)
	}
	if got := sealedToLost(t, v.Root); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("after the second loss: %q, want [a]", got)
	}
}

// Without a snapshot (set aside by an older jit) nothing can say which
// secrets the new key opens: every one is reported rather than none, and an
// import settles it, saying it could not check.
func TestSealedToLostKeyWithoutASnapshotFailsClosed(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a", "b")
	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(v.Root, lostKeySnapshotFile)); err != nil {
		t.Fatal(err)
	}
	setSecrets(t, v, "a")
	got, known, err := SealedToLostKey(v.Root)
	if err != nil || known || !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("no snapshot: %q known=%v err=%v, want every path and known=false", got, known, err)
	}
	remaining, unknown, err := SettleLostKey(v.Root, time.Now())
	if err != nil || !unknown || remaining != nil {
		t.Fatalf("settle without a snapshot: remaining=%q unknown=%v err=%v", remaining, unknown, err)
	}
	if got, _, _ := SealedToLostKey(v.Root); got != nil {
		t.Fatalf("still reported after settling: %q", got)
	}
}
