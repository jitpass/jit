// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/vault"
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

// withKeychainItem makes the keychain item under the vault key's name answer
// each presence check in turn (the last answer repeats), and counts deletes.
func withKeychainItem(t *testing.T, answers ...keystore.Presence) (deletes *int) {
	t.Helper()
	deletes = new(int)
	origP, origD := keychainCopyPresence, deleteLeftoverKey
	keychainCopyPresence = func() keystore.Presence {
		p := answers[0]
		if len(answers) > 1 {
			answers = answers[1:]
		}
		return p
	}
	deleteLeftoverKey = func() error { *deletes++; return nil }
	t.Cleanup(func() { keychainCopyPresence, deleteLeftoverKey = origP, origD })
	return deletes
}

// `jit vault delete` of an enclave vault whose keychain copy won't go: the
// warning names the keychain copy (not the enclave key, which did go), and
// the marker that stops the next init adopting it is written.
func TestVaultDeleteSaysWhichKeyStayed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		left       keystore.Presence
		want       []string
		notWant    string
		wantMarker bool
	}{
		{
			name:       "the keychain copy stayed",
			err:        fmt.Errorf("%w: delete failed, OSStatus=-25244", keystore.ErrKeychainCopyKept),
			left:       keystore.Present,
			want:       []string{"warning: couldn't delete the keychain copy of the vault key: delete failed, OSStatus=-25244", "Removed the vault's key in this Mac's Secure Enclave", "under the vault key's name", "jit vault init won't reuse it"},
			notWant:    "couldn't delete the vault key in the Secure Enclave",
			wantMarker: true,
		},
		{
			name:    "the enclave key stayed",
			err:     fmt.Errorf("%w: OSStatus=-4", keystore.ErrEnclaveKeyKept),
			left:    keystore.Absent,
			want:    []string{"warning: couldn't delete the vault key in the Secure Enclave: OSStatus=-4"},
			notWant: "keychain copy",
		},
		{
			name:       "the keychain would not say",
			left:       keystore.Indeterminate,
			want:       []string{"under the vault key's name"},
			wantMarker: true,
		},
		{name: "both gone", left: keystore.Absent, want: []string{"Removed the vault's key in this Mac's Secure Enclave"}, notWant: "warning"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFixtureHome(t)
			root := seedFixtureVault(t, "fixture/API_KEY")
			plantSealedKeyFile(t, root)
			deleted := &[]keystore.Kind{}
			origOpen := openKeyStore
			openKeyStore = func(string) keystore.Store {
				return recordingStore{kind: keystore.KindSecureEnclave, deleted: deleted, deleteErr: tc.err}
			}
			origPresence := requireUserPresence
			requireUserPresence = func(string) error { return nil }
			vaultDeleteYes = true
			t.Cleanup(func() { openKeyStore, requireUserPresence, vaultDeleteYes = origOpen, origPresence, false })
			withKeychainItem(t, tc.left)

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
				t.Errorf("output blames the wrong key (%q):\n%s", tc.notWant, out)
			}
			_, statErr := os.Stat(filepath.Join(root, vault.LeftoverKeyMarker))
			if got := statErr == nil; got != tc.wantMarker {
				t.Errorf("leftover marker written = %v, want %v", got, tc.wantMarker)
			}
		})
	}
}

// After such a delete, `jit vault init` never adopts the item: it asks
// before deleting it, and stops on anything but a clear yes.
func TestVaultInitWontAdoptTheDeletedVaultsKey(t *testing.T) {
	setup := func(t *testing.T, answers ...keystore.Presence) (root string, deletes, inits *int) {
		withFixtureHome(t)
		var err error
		root, err = vaultRootDir()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, vault.LeftoverKeyMarker), []byte("left\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		inits = new(int)
		origOpen := openKeyStore
		openKeyStore = func(string) keystore.Store {
			return recordingStore{kind: keystore.KindKeychain, deleted: &[]keystore.Kind{}, inits: inits}
		}
		t.Cleanup(func() { openKeyStore = origOpen })
		return root, withKeychainItem(t, answers...), inits
	}
	markerLeft := func(root string) bool {
		_, err := os.Stat(filepath.Join(root, vault.LeftoverKeyMarker))
		return err == nil
	}

	t.Run("no, or no one to answer", func(t *testing.T) {
		for _, stdin := range []string{"n\n", ""} {
			root, deletes, inits := setup(t, keystore.Present)
			out, err := runRoot(t, stdin, "vault", "init")
			if err == nil || !strings.Contains(err.Error(), "won't reuse the deleted vault's key") {
				t.Fatalf("stdin %q: got %v, want a refusal\n%s", stdin, err, out)
			}
			assertShortLines(t, err.Error())
			if *deletes != 0 || *inits != 0 || !markerLeft(root) {
				t.Fatalf("stdin %q: deletes %d, inits %d, marker kept %v; want 0, 0, true", stdin, *deletes, *inits, markerLeft(root))
			}
			if !strings.Contains(out, "The vault you deleted left its key in your keychain.") {
				t.Errorf("the question was not asked:\n%s", out)
			}
		}
	})
	t.Run("yes: deleted, then a new key", func(t *testing.T) {
		root, deletes, inits := setup(t, keystore.Present, keystore.Absent)
		out, err := runRoot(t, "y\n", "vault", "init")
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if *deletes != 1 || *inits != 1 || markerLeft(root) {
			t.Fatalf("deletes %d, inits %d, marker kept %v; want 1, 1, false", *deletes, *inits, markerLeft(root))
		}
		if !strings.Contains(out, "Deleted the old vault's key from your keychain.") {
			t.Errorf("output:\n%s", out)
		}
	})
	t.Run("yes, and the item stays", func(t *testing.T) {
		root, _, inits := setup(t, keystore.Present, keystore.Present)
		_, err := runRoot(t, "y\n", "vault", "init")
		if err == nil || !strings.Contains(err.Error(), "still in your keychain") || *inits != 0 || !markerLeft(root) {
			t.Fatalf("got %v, inits %d, marker kept %v", err, *inits, markerLeft(root))
		}
	})
	t.Run("the item is already gone", func(t *testing.T) {
		root, deletes, inits := setup(t, keystore.Absent)
		if out, err := runRoot(t, "", "vault", "init"); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if *deletes != 0 || *inits != 1 || markerLeft(root) {
			t.Fatalf("deletes %d, inits %d, marker kept %v; want 0, 1, false", *deletes, *inits, markerLeft(root))
		}
	})
	t.Run("the keychain would not say", func(t *testing.T) {
		root, deletes, inits := setup(t, keystore.Indeterminate)
		_, err := runRoot(t, "y\n", "vault", "init")
		if err == nil || !strings.Contains(err.Error(), "couldn't check") || *deletes != 0 || *inits != 0 || !markerLeft(root) {
			t.Fatalf("got %v, deletes %d, inits %d, marker kept %v", err, *deletes, *inits, markerLeft(root))
		}
	})
	t.Run("the vault holds secrets again", func(t *testing.T) {
		root, deletes, inits := setup(t, keystore.Present)
		seedFixtureVault(t, "fixture/API_KEY")
		_, err := runRoot(t, "y\n", "vault", "init")
		if err == nil || !strings.Contains(err.Error(), "holds secrets again") || *deletes != 0 || *inits != 0 || !markerLeft(root) {
			t.Fatalf("got %v, deletes %d, inits %d, marker kept %v", err, *deletes, *inits, markerLeft(root))
		}
	})
	t.Run("the delete fails", func(t *testing.T) {
		root, _, inits := setup(t, keystore.Present)
		deleteLeftoverKey = func() error { return errors.New("delete failed, OSStatus=-25244") }
		_, err := runRoot(t, "y\n", "vault", "init")
		if err == nil || !strings.Contains(err.Error(), "-25244") || !strings.Contains(err.Error(), "Keychain Access") || *inits != 0 || !markerLeft(root) {
			t.Fatalf("got %v, inits %d, marker kept %v", err, *inits, markerLeft(root))
		}
	})
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
