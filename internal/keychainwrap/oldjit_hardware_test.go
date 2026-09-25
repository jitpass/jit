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
	"time"
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
	if oldJit == "" || os.Getenv("JIT_SE_TEST") != "1" {
		t.Skip("needs scripts/se-test.sh and JIT_KC_OLD_JIT: see TestHardwareDeleteAnOldJitsItem")
	}
	// No keychain dialog from here on, whatever a test does: one that would
	// have to ask fails instead (TestMain already did this for the run; it
	// is repeated so the helper stands on its own).
	DisallowKeychainUITesting()
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
// deleteItem's fallback (kw_item_delete_by_ref), with no dialog. Every item
// is TEST-ONLY, and keychain interaction is off for the whole run
// (DisallowKeychainUITesting), so no step can raise a dialog: one that
// would have to ask fails the test instead. It runs unattended:
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
	ownerEditPrecondition(t, w)
	if err := w.DeleteMEK(); err != nil {
		t.Fatalf("DeleteMEK, with the fallback: %v", err)
	}
	if w.MEKPresence() != MEKAbsent {
		t.Fatal("DeleteMEK reported success and the item is still there")
	}
}

// ownerEditPrecondition is every old-jit hardware test's built-in control:
// SecItemDelete alone must still refuse the old jit's item
// (errSecInvalidOwnerEdit) and leave it in place. If it no longer does,
// macOS changed, the test below it would pass without the fallback doing
// anything, and the test says so instead.
func ownerEditPrecondition(t *testing.T, w *Wrapper) {
	t.Helper()
	err := w.deleteMEKWithoutFallback()
	if err == nil {
		t.Fatal("SecItemDelete removed an older jit's item: the owner check S3g measured is gone; revisit the fallback")
	}
	if !strings.Contains(err.Error(), "-25244") {
		t.Fatalf("SecItemDelete failed differently from S3g: %v", err)
	}
	if w.MEKPresence() != MEKPresent {
		t.Fatal("the failed delete removed the item after all")
	}
}

// TestHardwarePromoteOverAnOldJitsItem: a rotation's promote (setMEK:
// deleteItem, then add) over an older jit's primary item. Its delete is the
// one that needs the fallback, which the control shows first.
func TestHardwarePromoteOverAnOldJitsItem(t *testing.T) {
	w := oldJitItem(t)
	ownerEditPrecondition(t, w)
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

// TestHardwareInstallOverAnOldJitsItem is the keychain half of a move back
// (`jit vault rekey --wrapper keychain`) finding an older jit's item under
// the vault key's name. InstallMEK never deletes an existing item, so the
// fallback is not on this path, and the test pins why: the same key is
// already the answer (nothing written), and a different key is refused
// with the old item left exactly as it was. The control shows the item is
// one only the fallback could have deleted, so "left alone" is not luck.
func TestHardwareInstallOverAnOldJitsItem(t *testing.T) {
	w := oldJitItem(t)
	ownerEditPrecondition(t, w)
	old, err := w.FetchMEK("")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if same, err := w.MatchesMEK(bytes.Repeat([]byte{1}, mekSize)); err != nil || same {
		t.Fatalf("MatchesMEK on other bytes: %v, %v", same, err)
	}

	if err := w.InstallMEK(old); err != nil {
		t.Fatalf("InstallMEK of the key already there: %v", err)
	}
	if same, err := w.MatchesMEK(old); err != nil || !same {
		t.Fatalf("after installing the same key: same=%v err=%v", same, err)
	}

	other := bytes.Repeat([]byte{2}, mekSize)
	err = w.InstallMEK(other)
	if err == nil || !strings.Contains(err.Error(), "different master key") {
		t.Fatalf("InstallMEK of a different key over an old jit's item: %v, want a refusal", err)
	}
	if same, err := w.MatchesMEK(old); err != nil || !same {
		t.Fatalf("the refusal changed the old jit's item: same=%v err=%v", same, err)
	}
}

// TestHardwareCountOpensOnAnOldJitsItem: keystore's check of a key left in
// the keychain when an enclave key is lost reads it quietly (no challenge,
// no dialog). On an older jit's item that read must still work, or the
// original key could never be recognised. Its control: in the same run, a
// key wrapped under other bytes does not count.
func TestHardwareCountOpensOnAnOldJitsItem(t *testing.T) {
	w := oldJitItem(t)
	old, err := w.FetchMEK("")
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(old)
	w.Close()
	dek := bytes.Repeat([]byte{5}, 32)
	mine, err := seal(old, dek, []byte("manual"))
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := seal(bytes.Repeat([]byte{6}, mekSize), dek, []byte("manual"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := w.CountOpens([]WrappedKey{{mine, "manual"}, {theirs, "manual"}})
	if err != nil {
		t.Fatalf("the quiet read of an old jit's item: %v", err)
	}
	if n != 1 {
		t.Fatalf("opened %d of 2, want exactly the one wrapped under the old jit's key", n)
	}
}

// TestHardwareGrantKeyDeleteAnOldJitsItem: the service's grant and job key
// delete (GrantKeys.Delete) over a key another jit made at another path, as
// a switch between the tarball or cask and the app leaves behind (S3g:
// the creator's PATH decides). SecItemDelete alone refuses it (the
// control), so without a fallback a revoked grant's key would stay and the
// unused-key cleanup would fail on it at every start. The service's
// fallback deletes it through its reference without the process-wide
// interaction switch. This half runs with interaction off for the whole
// binary, so it cannot raise a dialog: a delete that needed one would fail.
func TestHardwareGrantKeyDeleteAnOldJitsItem(t *testing.T) {
	w := oldJitItem(t)
	ownerEditPrecondition(t, w)
	if uiAllowed() {
		t.Fatal("keychain interaction is on; this half must run with it off")
	}
	if err := (GrantKeys{service: oldJitService}).Delete(w.account); err != nil {
		t.Fatalf("GrantKeys.Delete of an older jit's key: %v", err)
	}
	if w.MEKPresence() != MEKAbsent {
		t.Fatal("GrantKeys.Delete reported success and the key is still there")
	}
}

// TestHardwareGrantKeyDeleteAnOldJitsItemWithInteractionAllowed is the same
// delete as the service runs it: keychain interaction ON, as it is in the
// service, and left alone by the delete. No dialog may appear, and none
// can, because the delete needs no UI on such an item, shown before
// interaction is switched on, three ways:
//
//   - S3g row 8: SecKeychainItemDelete on an older jit's item, from another
//     binary, with interaction OFF, succeeded (three runs). A delete that
//     needed any UI would have failed errSecInteractionNotAllowed.
//   - S3g row 9: Apple's `security delete-generic-password`, a process with
//     interaction on, deleted the same item and returned at once.
//   - In this run: a first item of the same shape is deleted by this same
//     code with interaction OFF (so a UI need would fail it, not show), and
//     only if that works is a second one deleted with it ON.
//
// The lookup keeps kSecUseAuthenticationUIFail either way. The delete must
// finish at once (a dialog would hold it), succeed, and leave the switch as
// it found it.
func TestHardwareGrantKeyDeleteAnOldJitsItemWithInteractionAllowed(t *testing.T) {
	first := oldJitItem(t)
	ownerEditPrecondition(t, first)
	if uiAllowed() {
		t.Fatal("keychain interaction is on before the gate; it must be off")
	}
	if err := (GrantKeys{service: oldJitService}).Delete(first.account); err != nil {
		t.Fatalf("the gate: with interaction off the delete failed (%v); not switching it on", err)
	}
	if first.MEKPresence() != MEKAbsent {
		t.Fatal("the gate: the key is still there; not switching interaction on")
	}

	w := oldJitItem(t)
	ownerEditPrecondition(t, w)
	t.Cleanup(func() { setUIAllowed(false) })
	setUIAllowed(true)
	start := time.Now()
	err := (GrantKeys{service: oldJitService}).Delete(w.account)
	took := time.Since(start)
	stillOn := uiAllowed()
	setUIAllowed(false)
	if err != nil {
		t.Fatalf("interaction on: GrantKeys.Delete of an older jit's key: %v", err)
	}
	if took > 2*time.Second {
		t.Errorf("interaction on: the delete took %s; a dialog may have held it", took)
	}
	if !stillOn {
		t.Error("the service's delete switched keychain interaction off; it must leave it alone")
	}
	if w.MEKPresence() != MEKAbsent {
		t.Fatal("interaction on: the delete reported success and the key is still there")
	}
	t.Logf("interaction on: deleted an older jit's key through its reference in %s", took)
}
