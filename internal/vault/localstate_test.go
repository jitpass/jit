// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDeleteLocalStateRemovesEverythingAndReportsIt: the secrets tree,
// device identity, and last-export marker must all be gone afterward, and
// each one that existed must be named in the returned list (that list is
// `jit vault delete`'s user-facing report). A root with nothing in it
// must succeed with an empty list, not error — delete on an already-gone
// vault is a no-op, not a failure.
func TestDeleteLocalStateRemovesEverythingAndReportsIt(t *testing.T) {
	root := t.TempDir()
	kw := identityWrapper{}
	v := &Vault{Root: root, KeyWrapper: kw, RecipientID: "test-device"}
	if err := v.Set("fixture/API_KEY", []byte("value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := EnsureDeviceID(root); err != nil {
		t.Fatalf("EnsureDeviceID: %v", err)
	}
	if err := RecordExport(root); err != nil {
		t.Fatalf("RecordExport: %v", err)
	}

	removed, err := DeleteLocalState(root)
	if err != nil {
		t.Fatalf("DeleteLocalState: %v", err)
	}
	if len(removed) != 3 {
		t.Errorf("removed = %v, want the secrets dir, device.id, and last-export (3 entries)", removed)
	}
	for _, name := range []string{"vault", "device.id", "last-export"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Errorf("%s still exists after DeleteLocalState", name)
		}
	}

	// Idempotent on an already-empty root.
	removed, err = DeleteLocalState(root)
	if err != nil {
		t.Fatalf("DeleteLocalState on empty root: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("second DeleteLocalState removed = %v, want nothing left to remove", removed)
	}
}

// identityWrapper is a no-op KeyWrapper for seeding fixture vaults in this
// package's own tests — wrap/unwrap are identity, fine for a vault that
// only ever round-trips within one test.
type identityWrapper struct{}

func (identityWrapper) WrapKey(dek []byte) ([]byte, error)       { return dek, nil }
func (identityWrapper) UnwrapKey(wrapped []byte) ([]byte, error) { return wrapped, nil }
