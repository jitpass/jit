// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/secureenclave"
	"github.com/jitpass/jit/internal/vault"
)

// A Store's fetcher is what agent.NewServer builds per unlock; if it stopped
// being a ClosableFetcher the agent would silently skip wiping it.
var _ agent.ClosableFetcher = Fetcher(nil)

// Nothing here calls Presence, Init or Delete on the real backend: those
// reach the production keychain item, and keychainwrap's TEST-ONLY rule says
// no test may (its package comment has the incident). Construction is safe:
// keychainwrap.New touches nothing until used.

// TestMain disarms deleteKeychainCopy for the whole package before any test
// runs: enclaveStore.Delete calls it, and the real one deletes the
// production vault key item. A test that wants it counts calls through
// withFakeEnclave.
func TestMain(m *testing.M) {
	deleteKeychainCopy = func() error { panic("a keystore test reached the production keychain item") }
	// Init over a lost key checks the production keychain for a leftover
	// key: no item there, unless a test says otherwise (withLeftover).
	leftoverPresence = func() Presence { return Absent }
	leftoverOpens = func(string) (KeyMeasure, error) { panic("a keystore test reached the production keychain item") }
	newKeychainKey = func() KeychainKey { panic("a keystore test reached the production keychain item") }
	os.Exit(m.Run())
}

func TestOpenWithoutASealedFileIsTheKeychain(t *testing.T) {
	if k := Open(t.TempDir()).Kind(); k != KindKeychain {
		t.Fatalf("Open chose %q for a vault with no sealed key file, want %q", k, KindKeychain)
	}
}

func TestOpenWithASealedFileIsTheEnclave(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, vault.SealedKeyFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if k := Open(root).Kind(); k != KindSecureEnclave {
		t.Fatalf("Open chose %q for a vault with a sealed key file, want %q", k, KindSecureEnclave)
	}
}

// A sealed file that cannot even be checked must not be read as "no sealed
// file": that would quietly use the keychain for an enclave vault.
func TestOpenFailsClosedWhenTheFileCannotBeChecked(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if k := Open(notADir).Kind(); k != KindSecureEnclave {
		t.Fatalf("an uncheckable sealed-file path chose %q, want %q", k, KindSecureEnclave)
	}
}

func TestSealedFileNameIsOneConstant(t *testing.T) {
	if secureenclave.SealedFile != vault.SealedKeyFile {
		t.Fatalf("secureenclave writes %q, keystore looks for %q", secureenclave.SealedFile, vault.SealedKeyFile)
	}
}

// fakeEnclave stands in for secureenclave.Wrapper; the real one needs a
// signed, provisioned binary (see internal/secureenclave).
type fakeEnclave struct {
	Wrapper
	Fetcher
	presence secureenclave.Presence
	deleted  *int
}

// kcCopyDeletes counts deleteKeychainCopy calls under withFakeEnclave.
var kcCopyDeletes int

func (f fakeEnclave) Presence() secureenclave.Presence { return f.presence }
func (f fakeEnclave) Delete() error                    { *f.deleted++; return nil }

func withFakeEnclave(t *testing.T, p secureenclave.Presence) *int {
	t.Helper()
	deleted := new(int)
	orig := newEnclaveWrapper
	newEnclaveWrapper = func(string) enclaveWrapper { return fakeEnclave{presence: p, deleted: deleted} }
	origCopy := deleteKeychainCopy
	kcCopyDeletes = 0
	deleteKeychainCopy = func() error { kcCopyDeletes++; return nil }
	t.Cleanup(func() { newEnclaveWrapper, deleteKeychainCopy = orig, origCopy })
	return deleted
}

func TestEnclavePresenceMapping(t *testing.T) {
	for in, want := range map[secureenclave.Presence]Presence{
		secureenclave.Present:       Present,
		secureenclave.Absent:        Indeterminate, // the file vanished after Open: not proof of no key
		secureenclave.KeyLost:       KeyLost,
		secureenclave.Unavailable:   Unavailable,
		secureenclave.NeedsNewerJit: NeedsNewerJit, // never KeyLost: the key may be fine
		secureenclave.Indeterminate: Indeterminate,
	} {
		withFakeEnclave(t, in)
		if got := (enclaveStore{root: t.TempDir()}).Presence(); got != want {
			t.Errorf("secureenclave %v mapped to %v, want %v", in, got, want)
		}
	}
}

// `jit vault init` over an enclave vault creates nothing: a new key would
// open none of the existing secrets, so a lost key must say so.
func TestEnclaveInitConfirmsRatherThanCreates(t *testing.T) {
	withFakeEnclave(t, secureenclave.Present)
	if res, err := (enclaveStore{}).Init(); err != nil || res != InitReady {
		t.Fatalf("Init over a present key: %v, %v", res, err)
	}
	// A lost key: the sealed file is set aside (kept, it names the old
	// key) and a keychain key is made, so a recovery file can be imported.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, vault.SealedKeyFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	withFakeEnclave(t, secureenclave.KeyLost)
	made := 0
	origInit := initKeychain
	initKeychain = func() error { made++; return nil }
	t.Cleanup(func() { initKeychain = origInit })
	if res, err := (enclaveStore{root: root}).Init(); err != nil || res != InitNewKey {
		t.Fatalf("Init over a lost key: %v, %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(root, LostSealedFile)); err != nil {
		t.Errorf("the lost sealed file was not kept aside: %v", err)
	}
	if k := Open(root).Kind(); k != KindKeychain || made != 1 {
		t.Errorf("after Init: backend %q, keychain keys made %d; want keychain and 1", k, made)
	}
	withFakeEnclave(t, secureenclave.Unavailable)
	if _, err := (enclaveStore{}).Init(); !errors.Is(err, secureenclave.ErrUnavailable) {
		t.Fatalf("Init unreachable: %v, want ErrUnavailable", err)
	}
}

// A vault sealed by a newer jit (a slot this jit does not know) is never
// treated as a lost key: Init sets nothing aside, makes no keychain key, and
// says to update jit.
func TestEnclaveInitOverANewerJitsSealedFileRefuses(t *testing.T) {
	root := t.TempDir()
	sealed := filepath.Join(root, vault.SealedKeyFile)
	if err := os.WriteFile(sealed, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	withFakeEnclave(t, secureenclave.NeedsNewerJit)
	origInit, origLeft := initKeychain, leftoverPresence
	initKeychain = func() error { t.Error("Init made a keychain key"); return nil }
	leftoverPresence = func() Presence { t.Error("Init looked for a leftover key"); return Absent }
	t.Cleanup(func() { initKeychain, leftoverPresence = origInit, origLeft })

	_, err := (enclaveStore{root: root}).Init()
	if !errors.Is(err, secureenclave.ErrSealedByNewerJit) || err.Error() != "this vault's key was sealed by a newer jit; update jit" {
		t.Fatalf("Init: %v, want the newer-jit refusal", err)
	}
	if _, err := os.Stat(sealed); err != nil {
		t.Fatalf("the sealed file was moved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, LostSealedFile)); err == nil {
		t.Fatal("the sealed file was set aside as a lost key")
	}
}

// Init over a lost key records which secrets were sealed to it, so status
// and doctor can keep saying a restore is pending after the new keychain key
// makes the vault look healthy. Without the record nothing would know.
func TestEnclaveInitOverALostKeyRecordsWhatItCannotOpen(t *testing.T) {
	root := t.TempDir()
	v := &vault.Vault{Root: root, KeyWrapper: identityWrapper{}, RecipientID: "TEST-ONLY"}
	if err := v.Set("fixture/API_KEY", []byte("TEST-ONLY value")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, vault.SealedKeyFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	withFakeEnclave(t, secureenclave.KeyLost)
	origInit := initKeychain
	initKeychain = func() error { return nil }
	t.Cleanup(func() { initKeychain = origInit })

	if _, err := (enclaveStore{root: root}).Init(); err != nil {
		t.Fatalf("Init over a lost key: %v", err)
	}
	sealed, known, err := vault.SealedToLostKey(root)
	if err != nil || !known || len(sealed) != 1 || sealed[0] != "fixture/API_KEY" {
		t.Fatalf("after Init: sealed to the lost key %q (known=%v, err=%v), want [fixture/API_KEY]", sealed, known, err)
	}
}

// identityWrapper stands in for a key: only file bytes matter here.
type identityWrapper struct{}

func (identityWrapper) WrapKey(dek []byte) ([]byte, error) { return append([]byte(nil), dek...), nil }
func (identityWrapper) UnwrapKey(wrapped []byte) ([]byte, error) {
	return append([]byte(nil), wrapped...), nil
}

func TestEnclaveDeleteDeletesTheEnclaveKey(t *testing.T) {
	deleted := withFakeEnclave(t, secureenclave.Present)
	if err := (enclaveStore{}).Delete(); err != nil || *deleted != 1 {
		t.Fatalf("Delete: err=%v, enclave deletes=%d, want 1", err, *deleted)
	}
}

// A keychain copy a move left behind is the same key; deleting the vault
// must take it too, or the next `jit vault init` keeps it (kw_ensure_mek
// reuses an item it finds) and the "new" vault runs on the old key.
func TestEnclaveDeleteAlsoDeletesAKeychainCopy(t *testing.T) {
	withFakeEnclave(t, secureenclave.Present)
	if err := (enclaveStore{}).Delete(); err != nil {
		t.Fatal(err)
	}
	if kcCopyDeletes != 1 {
		t.Fatalf("keychain copy deletes = %d, want 1", kcCopyDeletes)
	}
}

// Fresh per call is load-bearing: a wrapper caches the MEK for its whole
// life, so handing out one shared wrapper would let every later unlock or
// command skip its challenge.
func TestFetchersAndWrappersAreFreshEachTime(t *testing.T) {
	// The real constructor: building a keychainwrap.Wrapper touches no item.
	orig := newKeychainKey
	newKeychainKey = func() KeychainKey { return keychainwrap.New() }
	t.Cleanup(func() { newKeychainKey = orig })
	s := Open(t.TempDir())
	if s.NewFetcher() == s.NewFetcher() {
		t.Fatal("NewFetcher returned the same fetcher twice")
	}
	if s.NewWrapper() == s.NewWrapper() {
		t.Fatal("NewWrapper returned the same wrapper twice")
	}
}

func TestPresenceZeroValueIsIndeterminate(t *testing.T) {
	var p Presence
	if p != Indeterminate {
		t.Fatal("an unset Presence must never read as Absent or Present")
	}
}
