// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/secureenclave"
	"github.com/jitpass/jit/internal/vault"
)

// TestHardwareMoveRoundTrip moves a TEST-ONLY key into the real Secure
// Enclave and back, with the real dialogs, through the same keyMover the
// command uses. It never touches the vault's own key: the keychain item and
// the enclave tag are TEST-ONLY names the constructors refuse to go without.
//
// Three dialogs: the keychain's and the enclave's on the way in, the
// enclave's on the way back. Run by a person:
//
//	PKG=./internal/cli JIT_SE_INTERACTIVE=1 scripts/se-test.sh -test.run TestHardwareMoveRoundTrip
func TestHardwareMoveRoundTrip(t *testing.T) {
	if os.Getenv("JIT_SE_TEST") != "1" || os.Getenv("JIT_SE_INTERACTIVE") != "1" {
		t.Skip("real enclave and real dialogs: see this test's comment")
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	service := "com.jitpass.vault.mek.TEST-ONLY.move." + hex.EncodeToString(suffix)
	tag := "com.jitpass.vault.kek.TEST-ONLY.move." + hex.EncodeToString(suffix)
	root := t.TempDir()

	quiet := keychainwrap.NewTesting(service, "move", func(string) error { return nil })
	t.Cleanup(func() {
		_ = quiet.DeleteMEK()
		_ = secureenclave.NewTesting(root, tag).Delete()
	})
	if err := quiet.EnsureMEK(); err != nil {
		t.Fatal(err)
	}
	original, err := quiet.FetchMEK("")
	if err != nil {
		t.Fatal(err)
	}
	quiet.Close()

	mover := func() *keyMover {
		return newKeyMoverWith(root, &bytes.Buffer{},
			keychainwrap.NewTesting(service, "move", keychainwrap.Challenge),
			func() *secureenclave.Wrapper { return secureenclave.NewTesting(root, tag) },
			func() *secureenclave.Wrapper { return secureenclave.NewStagedTesting(root, tag) },
			func() {})
	}

	if err := mover().toEnclave(); err != nil {
		t.Fatalf("into the enclave: %v", err)
	}
	if quiet.MEKPresence() != keychainwrap.MEKAbsent {
		t.Fatal("the keychain copy survived the move into the enclave")
	}
	if _, err := os.Stat(filepath.Join(root, vault.SealedKeyFile)); err != nil {
		t.Fatalf("no sealed file after the move: %v", err)
	}
	if rekeyInProgress(root) {
		t.Fatal("the marker survived a completed move")
	}

	if err := mover().toKeychain(); err != nil {
		t.Fatalf("back to the keychain: %v", err)
	}
	back, err := quiet.FetchMEK("")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, original) {
		t.Fatal("the key that came back is not the key that went in")
	}
	if _, err := os.Stat(filepath.Join(root, vault.SealedKeyFile)); err == nil {
		t.Fatal("the sealed file survived the move back")
	}
}

// TestHardwareFinishMoveOverAnOldJitsItem is the owner's Mac on 2026-09-25,
// with TEST-ONLY names: a move into the enclave stopped at its last step
// because the helper could not delete the keychain copy an older jit had
// made (errSecInvalidOwnerEdit, S3g). The marker says "move secure-enclave",
// the sealed file is in place, the old item is still there. Re-running the
// move must finish it: delete the item (keychainwrap's fallback) and clear
// the marker, touching neither the enclave nor any dialog. The sealed file
// here is a stand-in; the resumed move only checks that it exists, and the
// enclave constructors fail the test if the move reaches for them.
//
// Unattended, no dialog: keychain interaction is off for the whole run
// (TestMain, under JIT_SE_TEST=1), so a step that would have to ask fails
// the test instead:
//
//	sh spike/secure-enclave-mek/s3g/build.sh
//	JIT_KC_OLD_JIT=$PWD/spike/secure-enclave-mek/s3g/out/oldjit IDENTIFIER=jit \
//	  PKG=./internal/cli scripts/se-test.sh -test.run TestHardwareFinishMoveOverAnOldJitsItem
func TestHardwareFinishMoveOverAnOldJitsItem(t *testing.T) {
	oldJit := os.Getenv("JIT_KC_OLD_JIT")
	if os.Getenv("JIT_SE_TEST") != "1" || oldJit == "" {
		t.Skip("needs se-test.sh and JIT_KC_OLD_JIT: see this test's comment")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if sig, _ := exec.Command("/usr/bin/codesign", "-dv", self).CombinedOutput(); !strings.Contains(string(sig), "\nIdentifier=jit\n") { // #nosec G204 -- fixed system tool, our own path
		t.Fatal("not signed with identifier jit: run through scripts/se-test.sh with IDENTIFIER=jit")
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	const service = "com.jitpass.spike.owner.TEST-ONLY" // s3g's old-jit build writes only this
	account := "move-" + hex.EncodeToString(suffix)
	tag := "com.jitpass.vault.kek.TEST-ONLY.owner." + hex.EncodeToString(suffix)
	kc := keychainwrap.NewTesting(service, account, func(string) error {
		t.Error("the resumed move asked for the keychain's Touch ID")
		return nil
	})
	t.Cleanup(func() {
		_ = kc.DeleteMEK()
		_ = exec.Command(oldJit, "delete", account).Run() // #nosec G204 -- the test's own TEST-ONLY helper
	})
	if out, err := exec.Command(oldJit, "create", account).CombinedOutput(); err != nil || !strings.Contains(string(out), "OSStatus=0 ") { // #nosec G204 -- as above
		t.Fatalf("the old jit could not create the item: %v\n%s", err, out)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, vault.SealedKeyFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	noEnclave := func() *secureenclave.Wrapper {
		t.Error("the resumed move reached for the enclave")
		return secureenclave.NewTesting(root, tag)
	}
	var out bytes.Buffer
	m := newKeyMoverWith(root, &out, kc, noEnclave, noEnclave, func() {})
	if err := m.writeMarker(wrapperSecureEnclave); err != nil {
		t.Fatal(err)
	}
	if kc.MEKPresence() != keychainwrap.MEKPresent {
		t.Fatal("the old jit's item is not there")
	}
	// The built-in control: SecItemDelete alone still refuses this item
	// (errSecInvalidOwnerEdit, S3g) and leaves it, so the finished move
	// below can only have removed it through keychainwrap's fallback.
	if err := kc.DeleteMEKWithoutFallbackTesting(); err == nil || !strings.Contains(err.Error(), "-25244") {
		t.Fatalf("SecItemDelete alone on the old jit's item: %v, want OSStatus=-25244 (S3g no longer holds)", err)
	}
	if kc.MEKPresence() != keychainwrap.MEKPresent {
		t.Fatal("the control's failed delete removed the item")
	}

	if err := m.toEnclave(); err != nil {
		t.Fatalf("finishing the move: %v", err)
	}
	if kc.MEKPresence() != keychainwrap.MEKAbsent {
		t.Fatalf("the old jit's item survived the finished move:\n%s", out.String())
	}
	if rekeyInProgress(root) {
		t.Fatal("the marker survived")
	}
	if !strings.Contains(out.String(), "Moved the vault key into the Secure Enclave") || strings.Contains(out.String(), "could not be deleted") {
		t.Fatalf("output:\n%s", out.String())
	}
}
