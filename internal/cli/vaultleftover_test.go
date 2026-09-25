// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/keystore"
)

// runRoot runs one jit command with stdin, returning everything it printed.
func runRoot(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return buf.String(), err
}

// `jit vault delete` when a key would not delete: the warning names the key
// that stayed, and a keychain item that stayed is named with the way out,
// because the next `jit vault init` reuses it (kw_ensure_mek keeps an item
// it finds; design/secure-enclave.md, "A key left in the keychain").
func TestVaultDeleteSaysWhichKeyStayed(t *testing.T) {
	const reuse = "Delete \"" + keystore.KeychainItemName + "\" in Keychain Access,\n" +
		"or a new vault made with jit vault init reuses it."
	for _, tc := range []struct {
		name    string
		kind    keystore.Kind
		err     error
		want    []string
		notWant string
	}{
		{
			name: "the enclave vault's keychain copy stayed",
			kind: keystore.KindSecureEnclave,
			err:  fmt.Errorf("%w: delete failed, OSStatus=-25244", keystore.ErrKeychainCopyKept),
			want: []string{
				"warning: couldn't delete the old copy of the vault key from your keychain\n" +
					"(delete failed, OSStatus=-25244).\n" + reuse,
				"Removed the vault's key in this Mac's Secure Enclave",
			},
			notWant: "couldn't delete the vault key in the Secure Enclave",
		},
		{
			name:    "the enclave key stayed",
			kind:    keystore.KindSecureEnclave,
			err:     fmt.Errorf("%w: OSStatus=-4", keystore.ErrEnclaveKeyKept),
			want:    []string{"warning: couldn't delete the vault key in the Secure Enclave: OSStatus=-4"},
			notWant: "Keychain Access",
		},
		{
			name: "both stayed",
			kind: keystore.KindSecureEnclave,
			err: errors.Join(fmt.Errorf("%w: OSStatus=-4", keystore.ErrEnclaveKeyKept),
				fmt.Errorf("%w: delete failed, OSStatus=-25244", keystore.ErrKeychainCopyKept)),
			want: []string{
				"warning: couldn't delete the vault key in the Secure Enclave: OSStatus=-4",
				"(delete failed, OSStatus=-25244).\n" + reuse,
			},
			notWant: "Removed the vault's key",
		},
		{
			name: "a keychain vault's key stayed",
			kind: keystore.KindKeychain,
			err:  errors.New("delete failed, OSStatus=-25244 (deleting it through its reference: OSStatus=-25308)"),
			want: []string{
				"warning: couldn't delete the vault key from your keychain\n" +
					"(delete failed, OSStatus=-25244 (deleting it through its reference: OSStatus=-25308)).\n" + reuse,
			},
			notWant: "Removed the vault's key",
		},
		{name: "both gone", kind: keystore.KindSecureEnclave, want: []string{"Removed the vault's key in this Mac's Secure Enclave"}, notWant: "warning"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFixtureHome(t)
			root := seedFixtureVault(t, "fixture/API_KEY")
			if tc.kind == keystore.KindSecureEnclave {
				plantSealedKeyFile(t, root)
			}
			deleted := &[]keystore.Kind{}
			origOpen := openKeyStore
			openKeyStore = func(string) keystore.Store {
				return recordingStore{kind: tc.kind, deleted: deleted, deleteErr: tc.err}
			}
			origPresence := requireUserPresence
			requireUserPresence = func(string) error { return nil }
			vaultDeleteYes = true
			t.Cleanup(func() { openKeyStore, requireUserPresence, vaultDeleteYes = origOpen, origPresence, false })

			out, err := runRoot(t, "", "vault", "delete")
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			if tc.notWant != "" && strings.Contains(out, tc.notWant) {
				t.Errorf("output says %q:\n%s", tc.notWant, out)
			}
			if len(*deleted) != 1 {
				t.Errorf("Delete called %d times, want 1", len(*deleted))
			}
			// Nothing is left in the vault root for a later command to
			// read: a key that stayed is the user's to delete, not a marker
			// that locks the next vault out.
			if entries, _ := os.ReadDir(root); len(entries) != 0 {
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				t.Errorf("the vault root still holds %q", names)
			}
		})
	}
}

// With the key left in the keychain, `jit vault init` goes on as it always
// has: no question, no refusal. The warning above is the whole of the
// handling (the trade-off in design/secure-enclave.md).
func TestVaultInitAfterADeleteThatLeftTheKey(t *testing.T) {
	withFixtureHome(t)
	inits := new(int)
	origOpen := openKeyStore
	openKeyStore = func(string) keystore.Store {
		return recordingStore{kind: keystore.KindKeychain, deleted: &[]keystore.Kind{}, inits: inits}
	}
	t.Cleanup(func() { openKeyStore = origOpen })
	out, err := runRoot(t, "", "vault", "init")
	if err != nil || *inits != 1 {
		t.Fatalf("init: %v, inits %d; want it to run\n%s", err, *inits, out)
	}
}

// A restore from a leftover key is said, never silent.
func TestVaultInitSaysItRestoredFromTheKeychain(t *testing.T) {
	withFixtureHome(t)
	origOpen := openKeyStore
	openKeyStore = func(string) keystore.Store {
		return recordingStore{kind: keystore.KindSecureEnclave, deleted: &[]keystore.Kind{}, initRes: keystore.InitRecovered, presence: keystore.Present}
	}
	t.Cleanup(func() { openKeyStore = origOpen })
	out, err := runRoot(t, "", "vault", "init")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"This Mac's Secure Enclave no longer has the vault key.",
		"Your keychain still had it, and it opens every secret.",
		"The vault key is in your keychain now; nothing needs restoring.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	assertShortLines(t, out)
}
