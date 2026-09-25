// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keystore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/secureenclave"
	"github.com/jitpass/jit/internal/vault"
)

// failingEnclave is a fake enclave whose Delete fails.
type failingEnclave struct {
	fakeEnclave
	err error
}

func (f failingEnclave) Delete() error { return f.err }

// `jit vault delete` must be able to say WHICH key stayed: the next step
// differs (a keychain copy left behind is one the next init would adopt).
func TestEnclaveDeleteSaysWhichKeyStayed(t *testing.T) {
	boom := errors.New("OSStatus=-25244")
	for _, tc := range []struct {
		name               string
		enclaveErr, kcErr  error
		wantEnclave, wantK bool
	}{
		{"both gone", nil, nil, false, false},
		{"the keychain copy stayed", nil, boom, false, true},
		{"the enclave key stayed", boom, nil, true, false},
		{"both stayed", boom, boom, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig, origCopy := newEnclaveWrapper, deleteKeychainCopy
			newEnclaveWrapper = func(string) enclaveWrapper { return failingEnclave{err: tc.enclaveErr} }
			deleteKeychainCopy = func() error { return tc.kcErr }
			t.Cleanup(func() { newEnclaveWrapper, deleteKeychainCopy = orig, origCopy })

			err := (enclaveStore{root: t.TempDir()}).Delete()
			if (err == nil) != (!tc.wantEnclave && !tc.wantK) {
				t.Fatalf("err = %v", err)
			}
			if got := errors.Is(err, ErrEnclaveKeyKept); got != tc.wantEnclave {
				t.Errorf("ErrEnclaveKeyKept = %v, want %v (err %v)", got, tc.wantEnclave, err)
			}
			if got := errors.Is(err, ErrKeychainCopyKept); got != tc.wantK {
				t.Errorf("ErrKeychainCopyKept = %v, want %v (err %v)", got, tc.wantK, err)
			}
			if err != nil && !strings.Contains(err.Error(), "-25244") {
				t.Errorf("the keychain's own answer is missing from %q", err)
			}
		})
	}
}

// withLeftover makes Init over a lost key find a keychain item that opens
// opened of total secrets (or fails to say, with err), and counts how often
// it was measured and how many keychain keys were made.
func withLeftover(t *testing.T, p Presence, opened, total int, err error) (measured, made *int) {
	t.Helper()
	measured, made = new(int), new(int)
	origP, origO, origI := leftoverPresence, leftoverOpens, initKeychain
	leftoverPresence = func() Presence { return p }
	leftoverOpens = func(string) (int, int, error) { *measured++; return opened, total, err }
	initKeychain = func() error { *made++; return nil }
	t.Cleanup(func() { leftoverPresence, leftoverOpens, initKeychain = origP, origO, origI })
	return measured, made
}

func lostKeyVault(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, vault.SealedKeyFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	withFakeEnclave(t, secureenclave.KeyLost)
	return root
}

// The enclave key is lost and the keychain holds the vault's own key (a move
// could not delete its copy): it opens every secret, so Init restores from
// it, says so, and records nothing as waiting for a restore.
func TestInitOverALostKeyRestoresFromTheVaultsOwnKey(t *testing.T) {
	root := lostKeyVault(t)
	measured, made := withLeftover(t, Present, 3, 3, nil)
	res, err := (enclaveStore{root: root}).Init()
	if err != nil || res != InitRecovered {
		t.Fatalf("Init = %v, %v; want InitRecovered", res, err)
	}
	if *measured != 1 || *made != 0 {
		t.Errorf("measured %d, keys made %d; want 1 and 0 (the item is the key)", *measured, *made)
	}
	if k := Open(root).Kind(); k != KindKeychain {
		t.Errorf("after the restore the vault opens from %q, want the keychain", k)
	}
	if _, err := os.Lstat(filepath.Join(root, LostSealedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a lost-key file was written: %v", err)
	}
	if kept, _ := filepath.Glob(filepath.Join(root, RecoveredSealedFile+"-*")); len(kept) != 1 {
		t.Errorf("the sealed file was not set aside under %s-*: %v", RecoveredSealedFile, kept)
	}
	if sealed, known, err := vault.SealedToLostKey(root); err != nil || !known || len(sealed) != 0 {
		t.Errorf("restore_pending would read %q (known=%v, err=%v), want nothing pending", sealed, known, err)
	}
}

// Anything short of "it opens every secret" is not adopted, and nothing
// changes: the sealed file stays, no key is made, no record is written.
func TestInitOverALostKeyRefusesALeftoverItCantVouchFor(t *testing.T) {
	for _, tc := range []struct {
		name          string
		p             Presence
		opened, total int
		err           error
		want          string
		wantMeasured  int
	}{
		{"a different key", Present, 0, 2, nil, "opens none of this vault's secrets", 1},
		{"some of the secrets", Present, 1, 2, nil, "only 1 of this vault's 2 secrets", 1},
		{"no secrets to try it on", Present, 0, 0, nil, "no secrets to try it on", 1},
		{"it can't be read without asking", Present, 0, 0, errors.New("OSStatus=-25308"), "-25308", 1},
		{"the keychain would not answer", Indeterminate, 0, 0, nil, "couldn't check your keychain", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := lostKeyVault(t)
			measured, made := withLeftover(t, tc.p, tc.opened, tc.total, tc.err)
			_, err := (enclaveStore{root: root}).Init()
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(strings.ToLower(err.Error()), "nothing changed") {
				t.Fatalf("Init = %v, want a refusal naming %q", err, tc.want)
			}
			if *made != 0 || *measured != tc.wantMeasured {
				t.Errorf("keys made %d, measured %d; want 0 and %d", *made, *measured, tc.wantMeasured)
			}
			if k := Open(root).Kind(); k != KindSecureEnclave {
				t.Errorf("the sealed file moved: the vault now opens from %q", k)
			}
			if _, err := os.Lstat(filepath.Join(root, LostSealedFile)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a lost-key record was written: %v", err)
			}
			if tc.p == Present && tc.err == nil && !strings.Contains(err.Error(), KeychainItemName) {
				t.Errorf("the refusal does not name the item to delete: %v", err)
			}
		})
	}
}

// keychainKeyOpens against real (TEST-ONLY) keychain items: the key the
// secrets were written under opens all of them, another key none, and a
// vault with no secrets is measured without reading the item at all.
func TestKeychainKeyOpensMeasuresTheItem(t *testing.T) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	const service = "com.jitpass.vault.mek.TEST-ONLY"
	item := func(name string) *keychainwrap.Wrapper {
		w := keychainwrap.NewTesting(service, name+"-"+hex.EncodeToString(suffix), func(string) error { return nil })
		t.Cleanup(func() { _ = w.DeleteMEK() })
		return w
	}
	mine, theirs, none := item("leftover"), item("other"), item("missing")
	for _, w := range []*keychainwrap.Wrapper{mine, theirs} {
		if err := w.EnsureMEK(); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	id, err := vault.EnsureDeviceID(root)
	if err != nil {
		t.Fatal(err)
	}
	if opened, total, err := keychainKeyOpens(root, none); err != nil || opened != 0 || total != 0 {
		t.Fatalf("empty vault: %d of %d, err %v; want 0 of 0 and no read", opened, total, err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: mine, RecipientID: id}
	for _, p := range []string{"fixture/A", "fixture/B"} {
		if err := v.Set(p, []byte("TEST-ONLY value")); err != nil {
			t.Fatal(err)
		}
	}
	if opened, total, err := keychainKeyOpens(root, mine); err != nil || opened != 2 || total != 2 {
		t.Errorf("the vault's own key: %d of %d, err %v; want 2 of 2", opened, total, err)
	}
	if opened, total, err := keychainKeyOpens(root, theirs); err != nil || opened != 0 || total != 2 {
		t.Errorf("another key: %d of %d, err %v; want 0 of 2", opened, total, err)
	}
	if _, _, err := keychainKeyOpens(root, none); err == nil {
		t.Error("no item, and no error")
	}
}

// A leftover item that can't be used as a key (here, not a master key's
// length) fails the same way on every run, so "try again" left a lost-key
// vault stuck for good. The refusal names the item, the way out, and what
// comes after it; and once the item is gone, the same Init makes a new key
// over the lost one.
func TestInitOverAnUnreadableLeftoverNamesTheWayOut(t *testing.T) {
	root := lostKeyVault(t)
	withLeftover(t, Present, 0, 0, fmt.Errorf("the keychain item %q is not a master key: 16 bytes, want 32", KeychainItemName))
	_, err := (enclaveStore{root: root}).Init()
	if err == nil {
		t.Fatal("Init adopted or replaced an item it couldn't read")
	}
	msg := err.Error()
	for _, want := range []string{"can't use", "16 bytes, want 32", "Nothing changed", `"` + KeychainItemName + `" in Keychain Access`, "`jit vault init` again"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "try again") {
		t.Errorf("the refusal still says to try again:\n%s", msg)
	}
	for _, line := range strings.Split(msg, "\n") {
		if n := len([]rune(line)); n > 76 {
			t.Errorf("line of %d characters: %q", n, line)
		}
	}
	// The way out works: with the item deleted, Init starts over.
	_, made := withLeftover(t, Absent, 0, 0, nil)
	if res, err := (enclaveStore{root: root}).Init(); err != nil || res != InitNewKey || *made != 1 {
		t.Fatalf("after the item is deleted: Init = %v, %v, keys made %d; want InitNewKey and one key", res, err, *made)
	}
}

// A LOCKED login keychain with the enclave key lost: presence says the item
// is there (metadata needs no unlock) and the quiet read fails at once with
// errSecAuthFailed, the statuses TestHardwareLockedKeychainNeverAsks
// measured. That says nothing about the item, which may be the vault's
// only key, so Init says the keychain may be locked and to run init again,
// and never advises deleting it. errSecInteractionNotAllowed, a read that
// would have had to ask, is the same.
func TestInitOverALockedKeychainNeverSaysDelete(t *testing.T) {
	for _, status := range []int32{-25293, -25308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			root := lostKeyVault(t)
			measured, made := withLeftover(t, Present, 0, 0, &keychainwrap.QuietReadError{
				Status: status,
				Msg:    fmt.Sprintf("reading the key in the keychain without asking failed, OSStatus=%d", status),
			})
			_, err := (enclaveStore{root: root}).Init()
			if err == nil {
				t.Fatal("Init went on over a keychain it couldn't read")
			}
			msg := err.Error()
			want := "the vault's Secure Enclave key is lost, and jit couldn't read\n" +
				"the key in your keychain under the vault key's name right now\n" +
				fmt.Sprintf("(OSStatus=%d): your keychain may be locked.\n", status) +
				"Nothing changed. Unlock it, then run `jit vault init` again"
			if msg != want {
				t.Errorf("got:\n%s\nwant:\n%s", msg, want)
			}
			for _, never := range []string{"Keychain Access", "delete", "Delete", KeychainItemName} {
				if strings.Contains(msg, never) {
					t.Errorf("the refusal says %q, over an item that may be the vault's only key:\n%s", never, msg)
				}
			}
			if *measured != 1 || *made != 0 {
				t.Errorf("measured %d, keys made %d; want 1 and 0", *measured, *made)
			}
			if k := Open(root).Kind(); k != KindSecureEnclave {
				t.Errorf("the sealed file moved: the vault now opens from %q", k)
			}
		})
	}
}
