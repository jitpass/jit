// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// A sealed key file left behind by `jit vault delete` would make the next
// `jit vault init` look like an enclave vault whose key is lost.
func TestDeleteLocalStateRemovesTheSealedKeyFile(t *testing.T) {
	root := t.TempDir()
	sealed := filepath.Join(root, SealedKeyFile)
	if err := os.WriteFile(sealed, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := DeleteLocalState(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sealed); !os.IsNotExist(err) {
		t.Fatalf("sealed key file survived DeleteLocalState (stat err %v)", err)
	}
	found := false
	for _, r := range removed {
		found = found || r == sealed
	}
	if !found {
		t.Errorf("DeleteLocalState did not report removing %s: %v", sealed, removed)
	}
}
