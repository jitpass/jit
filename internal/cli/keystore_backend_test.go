// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/vault"
)

// recordingStore is a keystore.Store that touches no real key. Its Kind is
// fixed when it is opened, exactly like keystore.Open's, which is what lets
// these tests catch a command that opens the store too late.
type recordingStore struct {
	kind     keystore.Kind
	deleted  *[]keystore.Kind
	presence keystore.Presence // zero value Indeterminate; see Presence

	deleteErr error               // what Delete answers
	inits     *int                // counts Init calls, when set
	initRes   keystore.InitResult // what Init answers
}

func (s recordingStore) Kind() keystore.Kind { return s.kind }
func (s recordingStore) Presence() keystore.Presence {
	if s.presence == keystore.Indeterminate {
		return keystore.Present
	}
	return s.presence
}
func (recordingStore) NewFetcher() keystore.Fetcher { panic("no key in a test") }
func (recordingStore) NewWrapper() keystore.Wrapper { panic("no key in a test") }
func (s recordingStore) Init() (keystore.InitResult, error) {
	if s.inits != nil {
		*s.inits++
	}
	return s.initRes, nil
}
func (s recordingStore) Delete() error {
	*s.deleted = append(*s.deleted, s.kind)
	return s.deleteErr
}

// stubKeyStores makes openKeyStore decide the way keystore.Open does (a
// sealed key file means the Secure Enclave) and returns the kinds whose
// Delete was called.
func stubKeyStores(t *testing.T) *[]keystore.Kind {
	t.Helper()
	deleted := &[]keystore.Kind{}
	orig := openKeyStore
	openKeyStore = func(root string) keystore.Store {
		kind := keystore.KindKeychain
		if _, err := os.Lstat(filepath.Join(root, vault.SealedKeyFile)); err == nil {
			kind = keystore.KindSecureEnclave
		}
		return recordingStore{kind: kind, deleted: deleted}
	}
	t.Cleanup(func() { openKeyStore = orig })
	return deleted
}

func plantSealedKeyFile(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, vault.SealedKeyFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The order bug B3 fixed: `jit vault delete` removed the vault's local
// state, sealed key file included, and only THEN asked which key to delete,
// so an enclave vault was answered "keychain" and its enclave key survived.
func TestVaultDeleteRemovesTheEnclaveKey(t *testing.T) {
	withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/API_KEY")
	plantSealedKeyFile(t, root)
	deleted := stubKeyStores(t)
	origPresence := requireUserPresence
	requireUserPresence = func(string) error { return nil }
	vaultDeleteYes = true
	t.Cleanup(func() { requireUserPresence = origPresence; vaultDeleteYes = false })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "delete"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault delete: %v\n%s", err, buf.String())
	}
	if len(*deleted) != 1 || (*deleted)[0] != keystore.KindSecureEnclave {
		t.Fatalf("deleted keys %v, want exactly the Secure Enclave one", *deleted)
	}
	if _, err := os.Stat(filepath.Join(root, vault.SealedKeyFile)); !os.IsNotExist(err) {
		t.Error("the sealed key file survived jit vault delete")
	}
	if !strings.Contains(buf.String(), "Secure Enclave") {
		t.Errorf("the report should say where the key was, got:\n%s", buf.String())
	}
}

// The same order, in `jit uninstall --purge`: the vault folder goes first,
// so the key's backend must be read before it does.
func TestUninstallPurgeDeletesTheEnclaveKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("ZDOTDIR", "")
	stubKeychain(t, keystore.Present)
	stubKeyStores(t)

	origLaunchctl, origDelete, origChallenge := launchctlRun, deleteVaultKeys, uninstallChallenge
	t.Cleanup(func() {
		launchctlRun, deleteVaultKeys, uninstallChallenge = origLaunchctl, origDelete, origChallenge
		uninstallPurge, uninstallYes, uninstallKeepBinary = false, false, false
	})
	launchctlRun = func(...string) ([]byte, error) { return nil, nil }
	var got keystore.Kind
	deleteVaultKeys = func(ks keystore.Store) error { got = ks.Kind(); return nil }
	uninstallChallenge = func(string) error { return nil }

	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	plantSealedKeyFile(t, root)

	uninstallPurge, uninstallYes, uninstallKeepBinary = true, true, true
	var out strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runUninstall(cmd, nil); err != nil {
		t.Fatalf("runUninstall: %v\n%s", err, out.String())
	}
	if got != keystore.KindSecureEnclave {
		t.Fatalf("uninstall --purge deleted the %q key, want %q", got, keystore.KindSecureEnclave)
	}
	if !strings.Contains(out.String(), "Secure Enclave") {
		t.Errorf("the report should say where the key was, got:\n%s", out.String())
	}
}

// Rekey rotates the keychain item; on an enclave vault it must refuse
// before it touches a key. (Not negative-controlled on purpose: without
// the refusal this test would read the production keychain item.)
func TestVaultRekeyRefusesAnEnclaveVault(t *testing.T) {
	withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/API_KEY")
	plantSealedKeyFile(t, root)
	stubKeyStores(t)
	vaultRekeyYes = true
	t.Cleanup(func() { vaultRekeyYes = false })

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "rekey"})
	err := rootCmd.Execute()
	const want = "jit vault rekey: this vault's key is in the Secure Enclave, and rotating it comes in a later version of jit"
	if err == nil || err.Error() != want {
		t.Fatalf("jit vault rekey on an enclave vault: %v, want %q", err, want)
	}
}

// A lost enclave key is the same loss as a missing keychain item, and doctor
// must say so in its own words.
func TestVaultKeyLostInTheEnclaveIsAHardProblem(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "aws/s3-access-key")
	stubKeychain(t, keystore.KeyLost)

	findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home))
	if len(findings) != 1 || findings[0].Kind != kindVaultKey {
		t.Fatalf("expected one vault_key finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Detail, "Secure Enclave") {
		t.Errorf("the finding should say the key is not in the Secure Enclave, got: %s", findings[0].Detail)
	}
}

func TestStatusReportsWhereTheKeyIsKept(t *testing.T) {
	home := withFixtureHome(t)
	stubKeychain(t, keystore.Present)
	stubKeyStores(t)
	got, err := gatherVaultStatus(fixtureVault(home), fixtureRoot(home))
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyStore != string(keystore.KindKeychain) {
		t.Fatalf("key_store = %q, want %q", got.KeyStore, keystore.KindKeychain)
	}
	if err := os.MkdirAll(fixtureRoot(home), 0o700); err != nil {
		t.Fatal(err)
	}
	plantSealedKeyFile(t, fixtureRoot(home))
	got, err = gatherVaultStatus(fixtureVault(home), fixtureRoot(home))
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyStore != string(keystore.KindSecureEnclave) {
		t.Fatalf("key_store = %q, want %q", got.KeyStore, keystore.KindSecureEnclave)
	}
}

// Review finding: after `jit uninstall --purge` removes the vault folder, an
// enclave store's Presence re-reads the (gone) sealed file, so the old
// "delete only if not Absent" guard always skipped the enclave key.
func TestDeleteVaultKeysDeletesEvenWhenPresenceSaysAbsent(t *testing.T) {
	orig := deleteStagedRekeyKey
	deleteStagedRekeyKey = func() error { return nil }
	t.Cleanup(func() { deleteStagedRekeyKey = orig })
	deleted := &[]keystore.Kind{}
	ks := recordingStore{kind: keystore.KindSecureEnclave, deleted: deleted, presence: keystore.Absent}
	if err := deleteVaultKeys(ks); err != nil {
		t.Fatal(err)
	}
	if len(*deleted) != 1 {
		t.Fatalf("Delete called %d times, want 1 even though Presence said Absent", len(*deleted))
	}
}

// Review finding: a jit that cannot reach an enclave vault, or whose enclave
// key is lost, must not offer first-run setup over it.
func TestFirstRunTreatsAnUnreachableOrLostEnclaveVaultAsSetUp(t *testing.T) {
	withFixtureHome(t)
	for _, c := range []struct {
		p    keystore.Presence
		want bool
	}{
		{keystore.Present, true},
		{keystore.KeyLost, true},
		{keystore.Unavailable, true},
		{keystore.Absent, false},
	} {
		orig := openKeyStore
		p := c.p
		openKeyStore = func(string) keystore.Store {
			return recordingStore{kind: keystore.KindSecureEnclave, deleted: &[]keystore.Kind{}, presence: p}
		}
		got := prodFirstRunDeps(rootCmd).vaultReady()
		openKeyStore = orig
		if got != c.want {
			t.Errorf("presence %v: vaultReady = %v, want %v", c.p, got, c.want)
		}
	}
}

// Review finding: a lost enclave key needs `jit vault init` before an import
// can land; the finding must say so.
func TestVaultKeyLostFindingSaysInitThenImport(t *testing.T) {
	home := withFixtureHome(t)
	plantVaultSecret(t, home, "aws/s3-access-key")
	stubKeychain(t, keystore.KeyLost)
	findings := gatherVaultIntegrityFindings(fixtureRoot(home), fixtureVault(home))
	if len(findings) != 1 {
		t.Fatalf("findings: %+v", findings)
	}
	if !strings.Contains(findings[0].Action, "jit vault init") || !strings.Contains(findings[0].Action, "jit vault import") {
		t.Errorf("action %q should name init, then import", findings[0].Action)
	}
}
