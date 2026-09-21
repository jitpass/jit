// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/vault"
)

// collectVaultNeedles reads every secret in the vault for `jit scan --deep`
// — the one place a scan authenticates, and only to READ (design/scan-and-
// protect.md D1, D2). openVault is the session-reuse path: no prompt when
// the service holds an unlocked session, one Touch ID otherwise; never
// openVaultFreshAuth, which is for commands about to write.
//
// A Mac with no vault yet gets a plain refusal before anything is read: a
// deep scan with nothing to look for would be a Touch ID for nothing. A
// secret that cannot be decrypted (a denied prompt, a torn envelope) fails
// the run rather than quietly narrowing it — a deep scan that silently
// checked half the vault would read as "nothing found" for the other half.
// The values are handed to the scanner and to nothing else.
func collectVaultNeedles() ([]audit.VaultNeedle, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, errors.New("no vault on this Mac yet; protect something first, then scan deep")
	}
	v, err := openVault()
	if err != nil {
		return nil, err
	}
	paths, err := v.List()
	if err != nil {
		return nil, fmt.Errorf("listing the vault: %w", err)
	}
	var needles []audit.VaultNeedle
	for _, p := range paths {
		if vault.IsReservedPath(p) {
			continue
		}
		val, err := v.Get(p)
		if err != nil {
			return nil, fmt.Errorf("reading %s from the vault: %w", p, err)
		}
		needles = append(needles, audit.VaultNeedle{Name: p, Value: string(val)})
	}
	if needles == nil {
		return nil, errors.New("the vault holds no secrets yet; protect something first, then scan deep")
	}
	return needles, nil
}
