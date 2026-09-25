// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// oldJitService is the TEST-ONLY service spike/secure-enclave-mek/s3g's
// program writes; its old-jit build (out/oldjit) is the only thing that
// creates items under it.
const oldJitService = "com.jitpass.spike.owner.TEST-ONLY"

// oldJitItem has the old-jit build create a TEST-ONLY item the way every
// released jit made the vault key (kw_ensure_mek's attributes), from a
// binary signed like one (identifier jit, the team's certificate, no
// entitlements) at a path that is not this test's. It returns a Wrapper
// over that item, deleted again when the test ends.
func oldJitItem(t *testing.T) *Wrapper {
	t.Helper()
	oldJit := os.Getenv("JIT_KC_OLD_JIT")
	if oldJit == "" {
		t.Skip("needs JIT_KC_OLD_JIT: see TestHardwareDeleteAnOldJitsItem")
	}
	// Reading the item is silent only for a binary whose code identifier is
	// jit (S3f). Any other signer gets the keychain's "wants to use your
	// confidential information" dialog, which this test must never raise.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := exec.Command("/usr/bin/codesign", "-dv", self).CombinedOutput() // #nosec G204 -- fixed system tool, our own path
	if !strings.Contains(string(sig), "\nIdentifier=jit\n") {
		t.Fatalf("this test binary is not signed with identifier jit, so reading the item would raise a keychain dialog; run it through scripts/se-test.sh with IDENTIFIER=jit")
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	account := "owner-" + hex.EncodeToString(suffix)
	w := NewTesting(oldJitService, account, func(string) error { return nil })
	t.Cleanup(func() {
		_ = w.DeleteMEK()
		_ = w.DeleteStagedRekeyMEK()
		_ = exec.Command(oldJit, "delete", account).Run() // #nosec G204 -- the test's own TEST-ONLY helper
	})
	out, err := exec.Command(oldJit, "create", account).CombinedOutput() // #nosec G204 -- as above
	if err != nil || !strings.Contains(string(out), "OSStatus=0 ") {
		t.Fatalf("the old jit could not create the item: %v\n%s", err, out)
	}
	return w
}

// TestHardwareDeleteAnOldJitsItem is S3g as a test: an item an older jit
// created, which the JitPass Agent helper can read, cannot be removed by
// SecItemDelete (errSecInvalidOwnerEdit, -25244), and is removed by
// kw_delete_mek's fallback, with no dialog. Every item is TEST-ONLY; no
// step can raise a dialog (none did in S3g), so it runs unattended:
//
//	sh spike/secure-enclave-mek/s3g/build.sh
//	JIT_KC_OLD_JIT=$PWD/spike/secure-enclave-mek/s3g/out/oldjit IDENTIFIER=jit \
//	  PKG=./internal/keychainwrap scripts/se-test.sh -test.run 'TestHardware.*OldJit'
//
// IDENTIFIER=jit signs the test bundle as the shipped helper is signed; with
// any other identifier the read would raise a keychain dialog, so the test
// refuses to run. Never run it as a plain `go test` binary for that reason.
func TestHardwareDeleteAnOldJitsItem(t *testing.T) {
	w := oldJitItem(t)
	if !w.HasMEK() {
		t.Fatal("this binary cannot read the old jit's item; S3g's premise does not hold here")
	}
	// The precondition, and the reason the fallback exists: if SecItemDelete
	// alone removes the item, macOS changed, and the fallback may be dead.
	err := w.deleteMEKWithoutFallback()
	if err == nil {
		t.Fatal("SecItemDelete removed an older jit's item: the owner check S3g measured is gone; revisit kwDeleteItems' fallback")
	}
	if !strings.Contains(err.Error(), "-25244") {
		t.Fatalf("SecItemDelete failed differently from S3g: %v", err)
	}
	if w.MEKPresence() != MEKPresent {
		t.Fatal("the failed delete removed the item after all")
	}
	if err := w.DeleteMEK(); err != nil {
		t.Fatalf("DeleteMEK, with the fallback: %v", err)
	}
	if w.MEKPresence() != MEKAbsent {
		t.Fatal("DeleteMEK reported success and the item is still there")
	}
}

// TestHardwareReplaceAnOldJitsItem: the other two writes that delete first.
// A rotation's promote (kw_set_mek) over an older jit's primary item, and a
// move back to the keychain finding the same key already there
// (InstallMEK), and the copy check before removing one (MatchesMEK).
func TestHardwareReplaceAnOldJitsItem(t *testing.T) {
	w := oldJitItem(t)
	old, err := w.FetchMEK("")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if same, err := w.MatchesMEK(old); err != nil || !same {
		t.Fatalf("MatchesMEK on the old jit's own bytes: %v, %v", same, err)
	}
	if same, err := w.MatchesMEK(bytes.Repeat([]byte{1}, mekSize)); err != nil || same {
		t.Fatalf("MatchesMEK on other bytes: %v, %v", same, err)
	}
	if err := w.InstallMEK(old); err != nil {
		t.Fatalf("InstallMEK of the key already there: %v", err)
	}

	if err := w.EnsureStagedRekeyMEK(); err != nil {
		t.Fatal(err)
	}
	next, err := w.StagedRekeyWrapper().FetchMEK("")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PromoteStagedRekeyMEK(); err != nil {
		t.Fatalf("promoting over an older jit's item: %v", err)
	}
	if same, err := w.MatchesMEK(next); err != nil || !same {
		t.Fatalf("after the promote the primary is not the staged key: %v, %v", same, err)
	}
	if w.StagedRekeyWrapper().MEKPresence() != MEKAbsent {
		t.Fatal("the staged item survived the promote")
	}
}
