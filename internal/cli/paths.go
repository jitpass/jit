// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jitpass/jit/internal/vault"
)

// vaultRootDir is plain path construction with no macOS-specific API calls
// — kept in a portable (non-darwin-gated) file so both vault.go
// (darwin-only, needs keychainwrap) and doctor.go (portable, only needs
// Vault.Exists/List, neither of which touches KeyWrapper) can share it
// without doctor.go picking up an unnecessary darwin build constraint.
func vaultRootDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "jitpass"), nil
}

// openVaultReadOnly returns a Vault usable for Exists/List — never Get/Set,
// since KeyWrapper is nil. Doctor's preflight only needs to confirm a
// secret's file exists, not decrypt it, so it never needs local auth.
// RecipientID comes from the same persisted device ID openVault uses (never
// os.Hostname(), which drifts — see vault.EnsureDeviceID); Exists/List never
// read it, but the two constructors must never disagree about what this
// device is called.
func openVaultReadOnly() (*vault.Vault, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	deviceID, err := vault.EnsureDeviceID(root)
	if err != nil {
		return nil, fmt.Errorf("determining device recipient ID: %w", err)
	}
	return &vault.Vault{Root: root, RecipientID: deviceID}, nil
}
