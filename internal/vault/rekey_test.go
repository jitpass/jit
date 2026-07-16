// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"bytes"
	"strings"
	"testing"
)

func rekeyTestVault(t *testing.T) (*Vault, *fakeKeyWrapper, *fakeKeyWrapper) {
	t.Helper()
	oldKW := newFakeKeyWrapper()
	newKW := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x99}, dekSize)}
	return &Vault{Root: t.TempDir(), KeyWrapper: oldKW, RecipientID: "test-device"}, oldKW, newKW
}

func TestRewrapAllMovesEverythingToTheNewKey(t *testing.T) {
	v, oldKW, newKW := rekeyTestVault(t)

	// A live secret, an overwrite (=> a _history version), and a backup —
	// all three envelope populations the walk must cover.
	if err := v.Set("stripe/dev-key", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("stripe/dev-key", []byte("second")); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("_backups/some/file", []byte("backup-bytes")); err != nil {
		t.Fatal(err)
	}

	rewrapped, current, err := v.RewrapAll(oldKW, newKW)
	if err != nil {
		t.Fatalf("RewrapAll: %v", err)
	}
	if rewrapped != 3 || current != 0 {
		t.Errorf("RewrapAll = (%d rewrapped, %d current), want (3, 0)", rewrapped, current)
	}

	// The vault decrypts under the NEW key...
	v.KeyWrapper = newKW
	if got, err := v.Get("stripe/dev-key"); err != nil || string(got) != "second" {
		t.Errorf("Get under new key = %q, %v; want second, nil", got, err)
	}
	// ...its history restores and still decrypts...
	if err := v.Restore("stripe/dev-key", 0); err != nil {
		t.Fatalf("Restore after rekey: %v", err)
	}
	if got, err := v.Get("stripe/dev-key"); err != nil || string(got) != "first" {
		t.Errorf("Get restored version under new key = %q, %v; want first, nil", got, err)
	}
	// ...and the OLD key opens nothing anymore.
	v.KeyWrapper = oldKW
	if _, err := v.Get("stripe/dev-key"); err == nil {
		t.Error("Get under the old key succeeded after rekey")
	}
}

func TestRewrapAllIsIdempotentAndResumable(t *testing.T) {
	v, oldKW, newKW := rekeyTestVault(t)
	if err := v.Set("a/one", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("b/two", []byte("2")); err != nil {
		t.Fatal(err)
	}

	if _, _, err := v.RewrapAll(oldKW, newKW); err != nil {
		t.Fatalf("first RewrapAll: %v", err)
	}
	// A second full run (crash-resume) finds everything current.
	rewrapped, current, err := v.RewrapAll(oldKW, newKW)
	if err != nil {
		t.Fatalf("second RewrapAll: %v", err)
	}
	if rewrapped != 0 || current != 2 {
		t.Errorf("resume RewrapAll = (%d, %d), want (0, 2)", rewrapped, current)
	}
	// The promote-crash resume shape: old key gone entirely.
	rewrapped, current, err = v.RewrapAll(nil, newKW)
	if err != nil {
		t.Fatalf("RewrapAll(nil, new): %v", err)
	}
	if rewrapped != 0 || current != 2 {
		t.Errorf("nil-old RewrapAll = (%d, %d), want (0, 2)", rewrapped, current)
	}
}

func TestRewrapAllFailsClosedWhenNeitherKeyOpensAnEnvelope(t *testing.T) {
	v, _, newKW := rekeyTestVault(t)
	if err := v.Set("a/one", []byte("1")); err != nil {
		t.Fatal(err)
	}
	// Old key vanished (interrupted promote) while this envelope is still
	// wrapped under it: the one unrecoverable-in-place state, which must
	// be a loud error, never a skip.
	_, _, err := v.RewrapAll(nil, newKW)
	if err == nil {
		t.Fatal("RewrapAll with an unopenable envelope succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot decrypt") {
		t.Errorf("error %q should name the undecryptable envelope problem", err)
	}
}
