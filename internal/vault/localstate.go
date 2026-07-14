// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// DeleteLocalState permanently removes every file this package keeps
// under root — the encrypted secrets tree, the device identity, and the
// last-export marker — returning which of them actually existed and were
// removed (for `jit vault delete`'s own report). The keychain-stored MEK
// is deliberately NOT this function's job: this package stays portable,
// and the keychain is internal/keychainwrap's darwin/CGo territory —
// `jit vault delete` composes the two. Removing device.id here is what
// makes a later `jit vault init` a genuinely fresh vault instead of one
// half-inheriting the old identity: every envelope is bound to the
// recipient ID, so a stale device.id under a new MEK would just make
// every future secret error confusingly instead of working.
func DeleteLocalState(root string) (removed []string, err error) {
	secretsDir := filepath.Join(root, "vault")
	if _, statErr := os.Stat(secretsDir); statErr == nil {
		if err := os.RemoveAll(secretsDir); err != nil {
			return removed, fmt.Errorf("removing the secrets directory: %w", err)
		}
		removed = append(removed, secretsDir)
	}
	for _, name := range []string{deviceIDFile, lastExportFile} {
		path := filepath.Join(root, name)
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removed, fmt.Errorf("removing %s: %w", path, err)
		}
		removed = append(removed, path)
	}
	return removed, nil
}
