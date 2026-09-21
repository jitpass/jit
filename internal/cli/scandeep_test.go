// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"os"
	"strings"
	"testing"
)

// A deep scan on a Mac with no vault is refused before anything is read —
// and, being refused, it creates no vault as a side effect.
func TestScanDeepNeedsAVaultAndCreatesNone(t *testing.T) {
	withFixtureHome(t)
	_, err := execScan(t, "--deep")
	if err == nil || !strings.Contains(err.Error(), "no vault on this Mac yet") {
		t.Fatalf("jit scan --deep without a vault: err = %v", err)
	}
	root, rootErr := vaultRootDir()
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	if _, statErr := os.Stat(root); statErr == nil {
		t.Fatalf("a refused deep scan created the vault root %s", root)
	}
}
