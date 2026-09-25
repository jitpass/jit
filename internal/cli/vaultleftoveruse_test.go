// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/vault"
)

// countingKeychainKey stands in for the vault key item: a working key (the
// package's fakeKeyWrapper) that counts every use.
type countingKeychainKey struct {
	kw   *fakeKeyWrapper
	uses *int
}

func (k countingKeychainKey) WrapKey(dek []byte) ([]byte, error) { *k.uses++; return k.kw.WrapKey(dek) }
func (k countingKeychainKey) UnwrapKey(w []byte) ([]byte, error) { *k.uses++; return k.kw.UnwrapKey(w) }
func (k countingKeychainKey) RequireUserPresence(string) error   { *k.uses++; return nil }
func (k countingKeychainKey) FetchMEK(string) ([]byte, error) {
	*k.uses++
	return append([]byte(nil), k.kw.key...), nil
}
func (countingKeychainKey) Close() {}

// leftoverVault is a keychain vault whose root holds `jit vault delete`'s
// leftover-key marker, with the key store opened through the real
// keystore logic over a counting stand-in for the item. It returns the root
// and the use count.
func leftoverVault(t *testing.T) (string, *int) {
	t.Helper()
	withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := vault.AtomicWriteFile(filepath.Join(root, vault.LeftoverKeyMarker), []byte("left by jit vault delete\n")); err != nil {
		t.Fatal(err)
	}
	uses := new(int)
	key := countingKeychainKey{kw: newFakeKeyWrapper(), uses: uses}
	orig := openKeyStore
	openKeyStore = func(r string) keystore.Store { return keystore.OpenTesting(r, key) }
	t.Cleanup(func() { openKeyStore = orig })
	return root, uses
}

// assertLeftoverRefusal: the command stopped on the leftover key, told the
// reader to run `jit vault init`, and never used the key.
func assertLeftoverRefusal(t *testing.T, err error, uses *int, out string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "the vault you deleted left its key in your keychain") ||
		!strings.Contains(err.Error(), "`jit vault init`") {
		t.Fatalf("got %v, want the leftover-key refusal\n%s", err, out)
	}
	if *uses != 0 {
		t.Fatalf("the leftover keychain key was used %d times", *uses)
	}
}

// `jit vault set` on a vault whose deleted predecessor left its key: refused
// before the key is touched, and nothing is written.
func TestVaultSetRefusesTheDeletedVaultsKey(t *testing.T) {
	root, uses := leftoverVault(t)
	out, err := runRoot(t, "", "vault", "set", "fixture/NEW", "TEST-ONLY-value")
	assertLeftoverRefusal(t, err, uses, out)
	if paths, _ := (&vault.Vault{Root: root}).List(); len(paths) != 0 {
		t.Fatalf("a secret was written under the leftover key: %v", paths)
	}
}

// `jit migrate` the same: the .env is left exactly as it was.
func TestMigrateRefusesTheDeletedVaultsKey(t *testing.T) {
	root, uses := leftoverVault(t)
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	// Built at run time, so no token-shaped literal sits in the source for
	// a secret scanner to stop a push on.
	body := []byte("STRIPE_SECRET_KEY=" + "sk_" + "live_" + "TESTONLY9f8e7d6c5b4a3f2e1d0c\n")
	if err := os.WriteFile(env, body, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := execMigrate(t, env, "--yes")
	migrateYes = false
	assertLeftoverRefusal(t, err, uses, out)
	if got, _ := os.ReadFile(env); !bytes.Equal(got, body) {
		t.Fatalf("the .env changed:\n%s", got)
	}
	if paths, _ := (&vault.Vault{Root: root}).List(); len(paths) != 0 {
		t.Fatalf("a secret was written under the leftover key: %v", paths)
	}
}

// The service's unlock, through the fetcher factory the service is built
// with (serviceFetchers): a client's first wrap asks the service to unlock,
// the unlock is refused with the same sentence, and the key is never used.
func TestServiceUnlockRefusesTheDeletedVaultsKey(t *testing.T) {
	root, uses := leftoverVault(t)
	socketPath := filepath.Join("/tmp", "jit-leftover-"+strings.ReplaceAll(t.Name(), "/", "-")[:8]+time.Now().Format("150405.000000")+".sock")
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	server := agent.NewServer(socketPath, serviceFetchers(root), time.Minute)
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = server.Close(); <-done })

	_, err := agent.NewClient(socketPath).WrapKey(bytes.Repeat([]byte{7}, 32))
	assertLeftoverRefusal(t, err, uses, "")
}

// `jit vault rekey`, which reaches the keychain item directly: a rotation
// would adopt the leftover key and a move would carry it into the enclave.
// Both refuse before touching anything. The rotation runs over a TEST-ONLY
// item and the move over the in-memory mover, so with the refusal removed
// (the negative control) neither can reach the vault's own key.
func TestVaultRekeyRefusesTheDeletedVaultsKey(t *testing.T) {
	root, uses := leftoverVault(t)
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	item := keychainwrap.NewTesting("com.jitpass.vault.mek.TEST-ONLY", "leftover-"+hex.EncodeToString(suffix), func(string) error { return nil })
	t.Cleanup(func() { _ = item.DeleteMEK(); _ = item.DeleteStagedRekeyMEK() })
	w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32)}
	w.startInKeychain()
	origRot, origMover := rotationKeychain, runMover
	rotationKeychain = func() *keychainwrap.Wrapper { return item }
	runMover = func(string, io.Writer) *keyMover { return w.mover() }
	t.Cleanup(func() { rotationKeychain, runMover = origRot, origMover })
	for _, args := range [][]string{
		{"vault", "rekey", "--yes"},
		{"vault", "rekey", "--wrapper", "secure-enclave", "--yes"},
	} {
		out, err := runRoot(t, "", args...)
		vaultRekeyYes, vaultRekeyWrapper = false, ""
		assertLeftoverRefusal(t, err, uses, out)
	}
	if item.MEKPresence() != keychainwrap.MEKAbsent {
		t.Error("the rotation made a key")
	}
	if len(w.prompts) != 0 || exists(filepath.Join(root, vault.SealedKeyFile)) {
		t.Errorf("the move ran: prompts %q", w.prompts)
	}
}
