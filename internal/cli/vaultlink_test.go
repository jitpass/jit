// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVaultLinkRejectsBadReferenceBeforeAnythingElse confirms a malformed
// reference fails shape validation before the trial resolve and before
// openVaultFreshAuth — a typo must cost neither an op exec nor a Touch ID
// prompt (same fail-before-prompting discipline as vault list/import).
func TestVaultLinkRejectsBadReferenceBeforeAnythingElse(t *testing.T) {
	vaultLinkYes, vaultLinkNoVerify = false, false
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)

	for _, ref := range []string{"not-a-reference", "https://example.com/x/y", "op://vault-only"} {
		rootCmd.SetArgs([]string{"vault", "link", "some/path", ref})
		err := rootCmd.Execute()
		if err == nil {
			t.Fatalf("vault link accepted %q, want a shape error", ref)
		}
		if !strings.Contains(err.Error(), "reference") {
			t.Errorf("error for %q does not explain the reference is bad: %v", ref, err)
		}
	}
}

// TestVaultLinkTrialResolveFailsClosedOnAnUnsignedOp pins the order of
// operations from the other side: with a PATH-planted fake `op`, the
// trial resolve must fail on signature verification — before any Touch ID
// — and the error must point at --no-verify as the offline escape.
func TestVaultLinkTrialResolveFailsClosedOnAnUnsignedOp(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "op")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf resolved\n"), 0o755); err != nil { // #nosec G306 -- a test's fake executable must be executable
		t.Fatalf("writing fake op: %v", err)
	}
	t.Setenv("PATH", dir)

	vaultLinkYes, vaultLinkNoVerify = false, false
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"vault", "link", "some/path", "op://vaultid/itemid/fieldid"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("vault link succeeded through an unsigned fake op, want a signature failure")
	}
	if !strings.Contains(err.Error(), "signature-verified") {
		t.Errorf("error does not name the signature check: %v", err)
	}
	if !strings.Contains(err.Error(), "--no-verify") {
		t.Errorf("error does not offer --no-verify: %v", err)
	}
}
