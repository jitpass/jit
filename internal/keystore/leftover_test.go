// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keystore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
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

// withLeftover makes Init over a lost key find a keychain item measured as
// m (or failing to say, with err), and counts how often it was measured
// and how many keychain keys were made.
func withLeftover(t *testing.T, p Presence, m KeyMeasure, err error) (measured, made *int) {
	t.Helper()
	measured, made = new(int), new(int)
	origP, origO, origI := leftoverPresence, leftoverOpens, initKeychain
	leftoverPresence = func() Presence { return p }
	leftoverOpens = func(string) (KeyMeasure, error) { *measured++; return m, err }
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
	measured, made := withLeftover(t, Present, KeyMeasure{Opened: 3, Total: 3}, nil)
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
// And the refusal advises removing the item only when the measure proved
// it opens none of this vault's secrets (read, every secret tried, none
// opened): every other refusal says what jit couldn't tell, never
// "delete", and leaves removing it to the person, recovery file first.
func TestInitOverALostKeyRefusesALeftoverItCantVouchFor(t *testing.T) {
	item := fmt.Sprintf("%q", KeychainItemName)
	yourChoice := "If your recovery file has your secrets, you can remove that key\n" +
		"yourself in Keychain Access (" + item + "),\n" +
		"run `jit vault init` again, then import the file;\n" +
		"jit can't tell whether that key is still needed"
	for _, tc := range []struct {
		name         string
		p            Presence
		m            KeyMeasure
		err          error
		want         string
		wantMeasured int
		proven       bool // the one refusal that may advise removing it
	}{
		{"a different key", Present, KeyMeasure{Opened: 0, Total: 2}, nil,
			"the vault's Secure Enclave key is lost.\n" +
				"A key in your keychain has the vault key's name, but it opens\n" +
				"none of this vault's 2 secrets. jit won't use it; nothing changed.\n" +
				"Remove " + item + " in Keychain Access,\n" +
				"then run `jit vault init` again", 1, true},
		{"some of the secrets", Present, KeyMeasure{Opened: 1, Total: 2}, nil,
			"the vault's Secure Enclave key is lost.\n" +
				"A key in your keychain has the vault key's name, and it opens\n" +
				"1 of this vault's 2 secrets. Removing it loses\n" +
				"that one unless your recovery file has it.\n" +
				"jit won't use it or remove it; nothing changed.\n" +
				"If your recovery file has your secrets, you can remove that key\n" +
				"yourself in Keychain Access (" + item + "),\n" +
				"run `jit vault init` again, then import the file", 1, false},
		{"most of the secrets", Present, KeyMeasure{Opened: 2, Total: 3}, nil,
			"the vault's Secure Enclave key is lost.\n" +
				"A key in your keychain has the vault key's name, and it opens\n" +
				"2 of this vault's 3 secrets. Removing it loses\n" +
				"those 2 unless your recovery file has them.\n" +
				"jit won't use it or remove it; nothing changed.\n" +
				"If your recovery file has your secrets, you can remove that key\n" +
				"yourself in Keychain Access (" + item + "),\n" +
				"run `jit vault init` again, then import the file", 1, false},
		{"no secrets to try it on", Present, KeyMeasure{}, nil,
			"the vault's Secure Enclave key is lost.\n" +
				"A key in your keychain has the vault key's name, but with no\n" +
				"secrets to try it on, jit can't tell whose it is.\n" +
				"jit won't use it; nothing changed.\n" + yourChoice, 1, false},
		// The finding: a secret whose envelope couldn't be read was dropped
		// from the measure, so "opens none of 2" was said, with the delete
		// advice, when only 1 had been tried.
		{"opens none of those it could try", Present, KeyMeasure{Opened: 0, Untested: 1, Total: 2}, nil,
			"the vault's Secure Enclave key is lost, and jit couldn't test\n" +
				"1 secret against the key in your keychain: its file couldn't be read.\n" +
				"Nothing changed; jit won't use that key or remove it.\n" +
				"Once jit can read them, run `jit vault init` again", 1, false},
		{"every secret untested", Present, KeyMeasure{Opened: 0, Untested: 3, Total: 3}, nil,
			"the vault's Secure Enclave key is lost, and jit couldn't test\n" +
				"3 secrets against the key in your keychain: their files couldn't be read.\n" +
				"Nothing changed; jit won't use that key or remove it.\n" +
				"Once jit can read them, run `jit vault init` again", 1, false},
		{"opens the rest", Present, KeyMeasure{Opened: 1, Untested: 1, Total: 2}, nil,
			"the vault's Secure Enclave key is lost, and jit couldn't test\n" +
				"1 secret against the key in your keychain: its file couldn't be read.\n" +
				"Nothing changed; jit won't use that key or remove it.\n" +
				"Once jit can read them, run `jit vault init` again", 1, false},
		{"the keychain would not answer", Indeterminate, KeyMeasure{}, nil,
			"the vault's Secure Enclave key is lost,\n" +
				"and jit couldn't check your keychain for a key under its name.\n" +
				"Nothing changed. If your keychain is locked, unlock it;\n" +
				"then run `jit vault init` again", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := lostKeyVault(t)
			measured, made := withLeftover(t, tc.p, tc.m, tc.err)
			_, err := (enclaveStore{root: root}).Init()
			if err == nil {
				t.Fatal("Init went on over an item it couldn't vouch for")
			}
			if err.Error() != tc.want {
				t.Errorf("got:\n%s\nwant:\n%s", err, tc.want)
			}
			assertNoDeleteAdvice(t, err.Error(), tc.proven)
			if *made != 0 || *measured != tc.wantMeasured {
				t.Errorf("keys made %d, measured %d; want 0 and %d", *made, *measured, tc.wantMeasured)
			}
			if k := Open(root).Kind(); k != KindSecureEnclave {
				t.Errorf("the sealed file moved: the vault now opens from %q", k)
			}
			if _, err := os.Lstat(filepath.Join(root, LostSealedFile)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a lost-key record was written: %v", err)
			}
		})
	}
}

// assertNoDeleteAdvice is the rule every refusal over a keychain item keeps:
// no "delete" at all, and removing the item is jit's advice (a line that
// starts "Remove") only when proven. Otherwise any mention of Keychain
// Access is the person's own choice, and names the recovery file first.
// Lines stay short.
func assertNoDeleteAdvice(t *testing.T, msg string, proven bool) {
	t.Helper()
	if strings.Contains(strings.ToLower(msg), "delete") {
		t.Errorf("the refusal says delete:\n%s", msg)
	}
	advises := strings.Contains(msg, "\nRemove ")
	if advises != proven {
		t.Errorf("advises removing the item: %v, want %v (proven to open none):\n%s", advises, proven, msg)
	}
	if at := strings.Index(msg, "Keychain Access"); at >= 0 && !proven {
		if rf := strings.Index(msg, "If your recovery file has your secrets, you can remove"); rf < 0 || rf > at {
			t.Errorf("Keychain Access is named without the recovery file first, as the person's choice:\n%s", msg)
		}
	}
	for _, line := range strings.Split(msg, "\n") {
		if n := len([]rune(line)); n > 76 {
			t.Errorf("line of %d characters: %q", n, line)
		}
	}
}

// KeychainKeyOpens against real (TEST-ONLY) keychain items: the key the
// secrets were written under opens all of them, another key none, and a
// vault with no secrets still has the item read.
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
	if m, err := KeychainKeyOpens(root, mine); err != nil || m != (KeyMeasure{}) {
		t.Fatalf("empty vault: %+v, %v; want nothing measured and the item read", m, err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: mine, RecipientID: id}
	for _, p := range []string{"fixture/A", "fixture/B"} {
		if err := v.Set(p, []byte("TEST-ONLY value")); err != nil {
			t.Fatal(err)
		}
	}
	if m, err := KeychainKeyOpens(root, mine); err != nil || m != (KeyMeasure{Opened: 2, Total: 2}) {
		t.Errorf("the vault's own key: %+v, %v; want 2 of 2", m, err)
	}
	if m, err := KeychainKeyOpens(root, theirs); err != nil || m != (KeyMeasure{Total: 2}) {
		t.Errorf("another key: %+v, %v; want 0 of 2", m, err)
	}
	if _, err := KeychainKeyOpens(root, none); err == nil {
		t.Error("no item, and no error")
	}
}

// The --force measure (KeychainKeyOpens) over TEST-ONLY items: it reads the
// item even in an empty vault, so a nil error always means the item was
// read, and a secret whose envelope can't be read is counted as untested,
// never as one the key does not open.
func TestKeychainKeyOpensForForceCountsWhatItCouldNotTry(t *testing.T) {
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
	mine, theirs, none := item("force-mine"), item("force-other"), item("force-missing")
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
	// Empty vault: the item is still read.
	if _, err := KeychainKeyOpens(root, none); err == nil {
		t.Fatal("empty vault, no item: no error, so the item was never read")
	}
	if m, err := KeychainKeyOpens(root, theirs); err != nil || m != (KeyMeasure{}) {
		t.Fatalf("empty vault: %+v, %v; want nothing measured and the item read", m, err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: mine, RecipientID: id}
	for _, p := range []string{"fixture/A", "fixture/B"} {
		if err := v.Set(p, []byte("TEST-ONLY value")); err != nil {
			t.Fatal(err)
		}
	}
	if m, err := KeychainKeyOpens(root, theirs); err != nil || m != (KeyMeasure{Opened: 0, Untested: 0, Total: 2}) {
		t.Fatalf("another key: %+v, %v; want 0 opened, 0 untested of 2", m, err)
	}
	// One envelope unreadable: untested, not "doesn't open".
	var envelopes []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(p, "fixture") {
			envelopes = append(envelopes, p)
		}
		return nil
	})
	if len(envelopes) != 2 {
		t.Fatalf("found envelopes %q, want 2", envelopes)
	}
	if err := os.WriteFile(envelopes[0], []byte("not an envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if m, err := KeychainKeyOpens(root, theirs); err != nil || m != (KeyMeasure{Opened: 0, Untested: 1, Total: 2}) {
		t.Fatalf("one envelope unreadable: %+v, %v; want 1 untested of 2", m, err)
	}
	if m, err := KeychainKeyOpens(root, mine); err != nil || m != (KeyMeasure{Opened: 1, Untested: 1, Total: 2}) {
		t.Fatalf("the vault's key, one envelope unreadable: %+v, %v; want 1 opened, 1 untested", m, err)
	}
}

// A leftover item that can't be used as a key (here, not a master key's
// length) fails the same way on every run, so "try again" left a lost-key
// vault stuck for good. Nothing about it was measured, so the way out is
// the person's own, recovery file first, never jit's "delete it"; and once
// the item is gone, the same Init makes a new key over the lost one.
func TestInitOverAnUnreadableLeftoverNamesTheWayOut(t *testing.T) {
	root := lostKeyVault(t)
	withLeftover(t, Present, KeyMeasure{}, fmt.Errorf("the keychain item %q is not a master key: 16 bytes, want 32", KeychainItemName))
	_, err := (enclaveStore{root: root}).Init()
	if err == nil {
		t.Fatal("Init adopted or replaced an item it couldn't read")
	}
	msg := err.Error()
	want := "the vault's Secure Enclave key is lost, and jit can't use\n" +
		"the key in your keychain under the vault key's name\n" +
		"(…ult.mek\" is not a master key: 16 bytes, want 32). Nothing changed.\n" +
		"If your recovery file has your secrets, you can remove that key\n" +
		"yourself in Keychain Access (\"" + KeychainItemName + "\"),\n" +
		"run `jit vault init` again, then import the file;\n" +
		"jit can't tell whether that key is still needed"
	if msg != want {
		t.Errorf("got:\n%s\nwant:\n%s", msg, want)
	}
	assertNoDeleteAdvice(t, msg, false)
	if strings.Contains(msg, "try again") {
		t.Errorf("the refusal still says to try again:\n%s", msg)
	}
	// The way out works: with the item removed, Init starts over.
	_, made := withLeftover(t, Absent, KeyMeasure{}, nil)
	if res, err := (enclaveStore{root: root}).Init(); err != nil || res != InitNewKey || *made != 1 {
		t.Fatalf("after the item is removed: Init = %v, %v, keys made %d; want InitNewKey and one key", res, err, *made)
	}
}

// A LOCKED login keychain with the enclave key lost: presence says the item
// is there (metadata needs no unlock) and the quiet read fails at once with
// errSecAuthFailed, the statuses TestHardwareLockedKeychainNeverAsks
// measured. That says nothing about the item, which may be the vault's
// only key, so Init says the keychain may be locked and to run init again,
// and never mentions removing it.
func TestInitOverALockedKeychainNeverSaysDelete(t *testing.T) {
	root := lostKeyVault(t)
	measured, made := withLeftover(t, Present, KeyMeasure{}, &keychainwrap.QuietReadError{
		Status: -25293,
		Msg:    "reading the key in the keychain without asking failed, OSStatus=-25293",
	})
	_, err := (enclaveStore{root: root}).Init()
	if err == nil {
		t.Fatal("Init went on over a keychain it couldn't read")
	}
	msg := err.Error()
	want := "the vault's Secure Enclave key is lost, and jit couldn't read\n" +
		"the key in your keychain under the vault key's name right now\n" +
		"(OSStatus=-25293): your keychain may be locked.\n" +
		"Nothing changed. Unlock it, then run `jit vault init` again"
	if msg != want {
		t.Errorf("got:\n%s\nwant:\n%s", msg, want)
	}
	for _, never := range []string{"Keychain Access", "delete", "Delete", "remove", KeychainItemName} {
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
}

// errSecInteractionNotAllowed (-25308) is not a lock (a locked keychain
// answers -25293): this copy of jit isn't on the item's access list, so
// every run fails the same way and "unlock it and try again" would be a
// dead end. Init says so plainly; the item may still be the vault's only
// key, so removing it is the person's choice, recovery file first, and
// never "delete".
func TestInitOverAKeyThisJitMayNotRead(t *testing.T) {
	root := lostKeyVault(t)
	measured, made := withLeftover(t, Present, KeyMeasure{}, &keychainwrap.QuietReadError{
		Status: -25308,
		Msg:    "reading the key in the keychain without asking failed, OSStatus=-25308",
	})
	_, err := (enclaveStore{root: root}).Init()
	if err == nil {
		t.Fatal("Init went on over a key it couldn't read")
	}
	msg := err.Error()
	want := "the vault's Secure Enclave key is lost, and this copy of jit\n" +
		"isn't allowed to read the key in your keychain under the vault\n" +
		"key's name (OSStatus=-25308); another copy of jit likely saved it.\n" +
		"Nothing changed.\n" +
		"If your recovery file has your secrets, you can remove that key\n" +
		"yourself in Keychain Access (\"" + KeychainItemName + "\"),\n" +
		"run `jit vault init` again, then import the file;\n" +
		"jit can't tell whether that key is still needed"
	if msg != want {
		t.Errorf("got:\n%s\nwant:\n%s", msg, want)
	}
	assertNoDeleteAdvice(t, msg, false)
	for _, never := range []string{"locked", "Unlock"} {
		if strings.Contains(msg, never) {
			t.Errorf("the refusal says %q for a read this jit isn't allowed to make:\n%s", never, msg)
		}
	}
	if *measured != 1 || *made != 0 {
		t.Errorf("measured %d, keys made %d; want 1 and 0", *measured, *made)
	}
	if k := Open(root).Kind(); k != KindSecureEnclave {
		t.Errorf("the sealed file moved: the vault now opens from %q", k)
	}
}
