// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
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
