// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/keychainwrap"
)

// quietReadErr is what keychainwrap's quiet read returns for status.
func quietReadErr(status int32) error {
	return &keychainwrap.QuietReadError{
		Status: status,
		Msg:    fmt.Sprintf("reading the key in the keychain without asking failed, OSStatus=%d", status),
	}
}

// errNotMasterKey is the quiet read finding an item of the wrong length.
var errNotMasterKey = fmt.Errorf("the keychain item %q %w: 16 bytes, want 32", "com.jitpass.vault.mek", keychainwrap.ErrNotAMasterKey)

// yourChoice is the way on from an item jit couldn't read or measure once
// the enclave has opened: the person's choice, never jit's advice.
const yourChoice = "The vault opens from the Secure Enclave and doesn't need that key;\n" +
	"jit can't tell whether anything else does. If nothing does,\n" +
	`you can remove it yourself in Keychain Access ("com.jitpass.vault.mek")`

// assertNoDeleteAdvice: the text never tells anyone to delete anything,
// and names no jit command that would fail the same way (never names
// --force when the item couldn't be read).
func assertNoDeleteAdvice(t *testing.T, text string, noForce bool) {
	t.Helper()
	if strings.Contains(strings.ToLower(text), "delete") {
		t.Errorf("the text says delete:\n%s", text)
	}
	if noForce && strings.Contains(text, "--force") {
		t.Errorf("the text names --force, whose measure fails the same way:\n%s", text)
	}
	assertShortLines(t, text)
}

// removeKeychainCopy's refusal when the item can't be read to compare it,
// by cause. -25293 is a locked keychain (measured): unlock and run it
// again. -25308 is this copy of jit not being allowed to read the item:
// running the command again fails the same way, and so would --force's
// measure, so neither is named; the enclave opened, so Keychain Access is,
// as the person's choice.
func TestRemoveKeychainCopyRefusalByCause(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"locked", quietReadErr(-25293),
			"couldn't read the key in your keychain under the vault key's name\n" +
				"(OSStatus=-25293): your keychain may be locked.\n" +
				"It was left alone. Unlock it, then run\n" +
				"`jit vault rekey --wrapper secure-enclave` again"},
		{"another jit's item", quietReadErr(-25308),
			"this copy of jit can't read the key in your keychain under the\n" +
				"vault key's name (OSStatus=-25308); another copy of jit likely saved it.\n" +
				"It was left alone.\n" + yourChoice},
		{"not a master key", errNotMasterKey,
			"couldn't use the key in your keychain under the vault key's name\n" +
				"(it isn't a master key).\n" +
				"It was left alone.\n" + yourChoice},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newMoveWorld(t)
			w.startInEnclave()
			w.kc = append([]byte(nil), w.mek...)
			w.failMatch = tc.err
			err := w.mover().toEnclaveAs(planRemoveCopy, false)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got:\n%v\nwant:\n%s", err, tc.want)
			}
			assertNoDeleteAdvice(t, err.Error(), true)
			if !bytes.Equal(w.kc, w.mek) {
				t.Fatal("the item went")
			}
		})
	}
}

// --force's refusal when the item can't be measured, by the same causes.
func TestForceCheckRefusalByCause(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"locked", quietReadErr(-25293),
			"jit couldn't check whether the key in your keychain\n" +
				"opens any of this vault's secrets (OSStatus=-25293):\n" +
				"your keychain may be locked. It was left alone.\n" +
				"Unlock it, then run\n" +
				"`jit vault rekey --wrapper secure-enclave --force` again"},
		{"another jit's item", quietReadErr(-25308),
			"this copy of jit can't read the key in your keychain (OSStatus=-25308),\n" +
				"so it couldn't check whether it opens any of this vault's secrets.\n" +
				"It was left alone.\n" + yourChoice},
		{"not a master key", errNotMasterKey,
			"jit couldn't check whether the key in your keychain\n" +
				"opens any of this vault's secrets (it isn't a master key).\n" +
				"It was left alone.\n" + yourChoice},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newMoveWorld(t)
			w.startInEnclave()
			other := bytes.Repeat([]byte{7}, 32)
			w.kc = append([]byte(nil), other...)
			w.failMatch = tc.err
			w.failOpens = tc.err
			err := w.mover().toEnclaveAs(planRemoveCopy, true)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got:\n%v\nwant:\n%s", err, tc.want)
			}
			// The locked case names --force: unlocking changes the answer.
			assertNoDeleteAdvice(t, err.Error(), tc.name != "locked")
			if !bytes.Equal(w.kc, other) {
				t.Fatal("--force deleted a key it could not measure")
			}
		})
	}
}

// The move into the enclave finished, but the keychain copy would not go.
// What it prints depends on why the item can't be read now (the quiet
// read after the delete), and on whether the enclave opened in this run:
// only then may Keychain Access be named. Never "delete it".
func TestCopyLeftWarningByCause(t *testing.T) {
	const head = "The vault key's keychain copy could not be deleted.\n" +
		"The keychain said: delete failed, OSStatus=-25244\n" +
		"An older jit elsewhere on this Mac can still read it.\n"
	for _, tc := range []struct {
		name    string
		read    error
		resumed bool // the enclave did not open in this run
		want    string
	}{
		{"locked", quietReadErr(-25293), false,
			"Your keychain may be locked (OSStatus=-25293). Unlock it,\n" +
				"then remove the copy with `jit vault rekey --wrapper secure-enclave`\n"},
		{"another jit's item, enclave opened", quietReadErr(-25308), false,
			"This copy of jit can't read it (OSStatus=-25308).\n" + yourChoice + "\n"},
		{"another jit's item, resumed", quietReadErr(-25308), true,
			"This copy of jit can't read it (OSStatus=-25308).\n" +
				"`jit vault rekey --wrapper secure-enclave` opens the vault key\n" +
				"in the Secure Enclave first, then says how that copy can go.\n"},
		{"not a master key, enclave opened", errNotMasterKey, false,
			"jit can't use it (it isn't a master key).\n" + yourChoice + "\n"},
		{"readable, enclave opened", nil, false,
			"To remove it: `jit vault rekey --wrapper secure-enclave`\n" +
				"Or remove it yourself in Keychain Access (\"com.jitpass.vault.mek\").\n"},
		{"readable, resumed", nil, true,
			"To remove it: `jit vault rekey --wrapper secure-enclave`\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newMoveWorld(t)
			if tc.resumed {
				w.startInEnclave()
				w.kc = append([]byte(nil), w.mek...)
				if err := w.mover().writeMarker(wrapperSecureEnclave); err != nil {
					t.Fatal(err)
				}
			} else {
				w.startInKeychain()
			}
			w.failDelete = errOwnerEdit
			w.failRead = tc.read
			m := w.mover()
			if err := m.toEnclave(); err != nil {
				t.Fatalf("the move failed: %v", err)
			}
			out := w.out.String()
			want := "Moved the vault key into the Secure Enclave. Every secret opens as before.\n" +
				stripHL(hlCmds(head+tc.want))
			if stripHL(out) != want {
				t.Fatalf("got:\n%s\nwant:\n%s", stripHL(out), want)
			}
			// The head says what failed (the keychain's own words); what
			// follows is the advice.
			assertNoDeleteAdvice(t, tc.want, true)
			assertShortLines(t, stripHL(out))
			if tc.resumed && strings.Contains(out, "Keychain Access") {
				t.Error("Keychain Access is named though the enclave did not open in this run")
			}
		})
	}
}

// stripHL removes the terminal highlighting hlCmds may add.
func stripHL(s string) string { return regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(s, "") }

// The move back to the keychain over an item under the vault key's name it
// can't read: refused, never written over, with nothing changed (the
// sealed file and the enclave key stay, the marker goes), worded by cause.
func TestMoveBackOverAnUnreadableItem(t *testing.T) {
	const kept = "Nothing changed; the vault key is still in the Secure Enclave.\n"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"locked", quietReadErr(-25293),
			"a key is already in your keychain under the vault key's name,\n" +
				"and jit couldn't read it (OSStatus=-25293): your keychain may be locked.\n" +
				kept +
				"Unlock it, then run `jit vault rekey --wrapper keychain` again"},
		{"another jit's item", quietReadErr(-25308),
			"a key is already in your keychain under the vault key's name,\n" +
				"and this copy of jit can't read it (OSStatus=-25308), so it won't\n" +
				"write over it; another copy of jit likely saved it.\n" +
				kept + yourChoice + ",\n" +
				"then run `jit vault rekey --wrapper keychain` again"},
		{"not a master key", errNotMasterKey,
			"a key is already in your keychain under the vault key's name,\n" +
				"and jit can't use it (it isn't a master key), so it won't write over it.\n" +
				kept + yourChoice + ",\n" +
				"then run `jit vault rekey --wrapper keychain` again"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newMoveWorld(t)
			w.startInEnclave()
			other := bytes.Repeat([]byte{7}, 32)
			w.kc = append([]byte(nil), other...)
			w.failInstall = fmt.Errorf("%w: %w", keychainwrap.ErrExistingKeyUnreadable, tc.err)
			err := w.mover().toKeychain()
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got:\n%v\nwant:\n%s", err, tc.want)
			}
			assertNoDeleteAdvice(t, err.Error(), true)
			if !bytes.Equal(w.kc, other) {
				t.Fatal("the item was written over")
			}
			if got, err := w.readSealed(w.real()); err != nil || !bytes.Equal(got, w.mek) {
				t.Fatalf("the sealed file no longer opens to the MEK: %v", err)
			}
			if rekeyInProgress(w.root) {
				t.Error("the marker was left: every vault change would be refused")
			}
		})
	}
}
