// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/vault"
)

// moveWorld is a keychain and an enclave in memory, with the sealed files on
// disk exactly where the real ones go, so the mover's own file checks see
// what production would.
type moveWorld struct {
	t    *testing.T
	root string
	mek  []byte

	kc         []byte // the keychain item; nil = absent
	enclaveKey bool   // the enclave key exists
	prompts    []string
	failFetch  error // kcFetch
	failStaged error // seOpenStaged
	failOpen   error // seOpen
	lie        bool  // seOpenStaged returns a different key
	failDelete error // kcDelete: the keychain refuses, as an older jit's item once did
	failMatch  error // kcMatches: the keychain item can't be read
	opens      int   // kcOpens: how many live secrets the item opens
	untested   int   // kcOpens: how many live secrets couldn't be tried (unreadable envelopes)
	failOpens  error // kcOpens: the item can't be measured
	measured   int   // kcOpens calls
	out        *bytes.Buffer

	// presence, when set, answers kcPresent in turn instead of w.kc (the
	// keychain changing its answer between two checks); presenceCalls
	// counts every kcPresent call.
	presence      []keystore.Presence
	presenceCalls int
}

func newMoveWorld(t *testing.T) *moveWorld {
	t.Helper()
	mek := make([]byte, 32)
	if _, err := rand.Read(mek); err != nil {
		t.Fatal(err)
	}
	return &moveWorld{t: t, root: t.TempDir(), mek: mek}
}

func (w *moveWorld) real() string   { return filepath.Join(w.root, vault.SealedKeyFile) }
func (w *moveWorld) staged() string { return w.real() + ".next" }

// startInKeychain / startInEnclave set the world up as a vault of each kind.
func (w *moveWorld) startInKeychain() { w.kc = append([]byte(nil), w.mek...) }

func (w *moveWorld) startInEnclave() {
	w.enclaveKey = true
	w.writeSealed(w.real(), w.mek)
}

// The fake "sealing" is hex: what matters here is where copies live and in
// what order they appear and go, not the cryptography (secureenclave's own
// tests and the hardware run cover that).
func (w *moveWorld) writeSealed(path string, mek []byte) {
	if err := os.WriteFile(path, []byte(hex.EncodeToString(mek)), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func (w *moveWorld) readSealed(path string) ([]byte, error) {
	if !w.enclaveKey {
		return nil, errors.New("fake enclave: no key")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(string(data))
}

func (w *moveWorld) mover() *keyMover {
	w.out = &bytes.Buffer{}
	return &keyMover{
		root: w.root,
		out:  w.out,
		kcPresent: func() keystore.Presence {
			w.presenceCalls++
			if len(w.presence) > 0 {
				p := w.presence[0]
				w.presence = w.presence[1:]
				return p
			}
			if w.kc == nil {
				return keystore.Absent
			}
			return keystore.Present
		},
		kcFetch: func(reason string) ([]byte, error) {
			w.prompts = append(w.prompts, "keychain: "+reason)
			if w.failFetch != nil {
				return nil, w.failFetch
			}
			if w.kc == nil {
				return nil, errors.New("fake keychain: no key")
			}
			return append([]byte(nil), w.kc...), nil
		},
		kcInstall: func(mek []byte) error {
			if w.kc != nil && !bytes.Equal(w.kc, mek) {
				return errors.New("fake keychain: a different key is already here")
			}
			w.kc = append([]byte(nil), mek...)
			return nil
		},
		kcDelete: func() error {
			if w.failDelete != nil {
				return w.failDelete
			}
			w.kc = nil
			return nil
		},
		kcMatches: func(mek []byte) (bool, error) {
			if w.failMatch != nil {
				return false, w.failMatch
			}
			if w.kc == nil {
				return false, errors.New("fake keychain: no key")
			}
			return bytes.Equal(w.kc, mek), nil
		},
		kcOpens: func() (keystore.KeyMeasure, error) {
			w.measured++
			return keystore.KeyMeasure{Opened: w.opens, Untested: w.untested, Total: w.opens + w.untested + 1}, w.failOpens
		},
		seInstallStaged: func(mek []byte) error {
			// Like secureenclave.Wrapper.Install: never seal over a file.
			if exists(w.staged()) {
				return errors.New("fake enclave: the staged file already exists")
			}
			w.enclaveKey = true
			w.writeSealed(w.staged(), mek)
			return nil
		},
		seOpenStaged: func(reason string) ([]byte, error) {
			w.prompts = append(w.prompts, "enclave: "+reason)
			if w.failStaged != nil {
				return nil, w.failStaged
			}
			got, err := w.readSealed(w.staged())
			if w.lie && err == nil {
				got[0] ^= 1
			}
			return got, err
		},
		sePromote: func() error { return os.Rename(w.staged(), w.real()) },
		seRemoveStaged: func() error {
			if err := os.Remove(w.staged()); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		},
		seOpen: func(reason string) ([]byte, error) {
			w.prompts = append(w.prompts, "enclave: "+reason)
			if w.failOpen != nil {
				return nil, w.failOpen
			}
			return w.readSealed(w.real())
		},
		seDelete: func() error {
			if err := os.Remove(w.real()); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			w.enclaveKey = false
			return nil
		},
		lockAgent: func() {},
	}
}

// recoverable is the move's one rule: some copy of the MEK that opens is
// always there. Either the keychain holds it, or the vault's sealed file
// does and the enclave key that opens it exists.
func (w *moveWorld) recoverable() bool {
	if bytes.Equal(w.kc, w.mek) {
		return true
	}
	got, err := w.readSealed(w.real())
	return err == nil && bytes.Equal(got, w.mek)
}

func (w *moveWorld) assertInEnclave() {
	w.t.Helper()
	if w.kc != nil {
		w.t.Error("the keychain copy survived the move into the enclave")
	}
	if got, err := w.readSealed(w.real()); err != nil || !bytes.Equal(got, w.mek) {
		w.t.Errorf("the vault's sealed file does not open to the MEK: %v", err)
	}
	w.assertSettled()
}

func (w *moveWorld) assertInKeychain() {
	w.t.Helper()
	if !bytes.Equal(w.kc, w.mek) {
		w.t.Error("the keychain does not hold the MEK")
	}
	if exists(w.real()) || w.enclaveKey {
		w.t.Errorf("enclave leftovers: sealed file %v, enclave key %v", exists(w.real()), w.enclaveKey)
	}
	w.assertSettled()
}

func (w *moveWorld) assertSettled() {
	w.t.Helper()
	if exists(w.staged()) {
		w.t.Error("a staged sealed file was left behind")
	}
	if rekeyInProgress(w.root) {
		w.t.Error("the marker was left behind")
	}
}

func TestMoveIntoTheEnclave(t *testing.T) {
	w := newMoveWorld(t)
	w.startInKeychain()
	if err := w.mover().toEnclave(); err != nil {
		t.Fatal(err)
	}
	w.assertInEnclave()
	// Two dialogs: the keychain's, to read the key; the enclave's, to prove
	// the sealed copy opens before the keychain copy goes.
	if len(w.prompts) != 2 || !strings.HasPrefix(w.prompts[0], "keychain:") || !strings.HasPrefix(w.prompts[1], "enclave:") {
		t.Errorf("prompts = %q", w.prompts)
	}
}

func TestMoveBackToTheKeychain(t *testing.T) {
	w := newMoveWorld(t)
	w.startInEnclave()
	if err := w.mover().toKeychain(); err != nil {
		t.Fatal(err)
	}
	w.assertInKeychain()
	if len(w.prompts) != 1 || !strings.HasPrefix(w.prompts[0], "enclave:") {
		t.Errorf("prompts = %q, want only the enclave's", w.prompts)
	}
}

// The heart of B4: kill the move after every step, in both directions. The
// key must be recoverable at the crash, the marker must hold every other
// command off, and re-running must finish the move.
func TestMoveSurvivesACrashAfterEveryStep(t *testing.T) {
	cases := []struct {
		dir   string
		steps []string
	}{
		{wrapperSecureEnclave, []string{"staged", "verified", "promoted", "keychain deleted"}},
		{wrapperKeychain, []string{"installed", "file removed", "enclave deleted"}},
	}
	for _, c := range cases {
		for _, at := range c.steps {
			t.Run(c.dir+"/"+at, func(t *testing.T) {
				w := newMoveWorld(t)
				run := func(m *keyMover) error {
					if c.dir == wrapperSecureEnclave {
						return m.toEnclave()
					}
					return m.toKeychain()
				}
				if c.dir == wrapperSecureEnclave {
					w.startInKeychain()
				} else {
					w.startInEnclave()
				}
				m := w.mover()
				m.crash = func(step string) error {
					if step == at {
						return errors.New("crash")
					}
					return nil
				}
				if err := run(m); err == nil {
					t.Fatalf("the injected crash at %q did not stop the move", at)
				}
				if !w.recoverable() {
					t.Fatalf("after a crash at %q no copy of the key opens", at)
				}
				if !rekeyInProgress(w.root) {
					t.Fatalf("after a crash at %q the marker is gone; other commands would not refuse", at)
				}
				if got := moveInProgress(w.root); got != c.dir {
					t.Fatalf("the marker names %q, want %q", got, c.dir)
				}
				if err := run(w.mover()); err != nil {
					t.Fatalf("re-running after a crash at %q: %v", at, err)
				}
				if c.dir == wrapperSecureEnclave {
					w.assertInEnclave()
				} else {
					w.assertInKeychain()
				}
			})
		}
	}
}

// A failure before the new copy exists changes nothing, so it must not leave
// the vault locked behind a marker either.
func TestMoveThatFailsEarlyLeavesTheVaultAsItWas(t *testing.T) {
	canceled := errors.New("local authentication failed: canceled")
	t.Run("keychain dialog canceled", func(t *testing.T) {
		w := newMoveWorld(t)
		w.startInKeychain()
		w.failFetch = canceled
		if err := w.mover().toEnclave(); !errors.Is(err, canceled) {
			t.Fatalf("got %v", err)
		}
		w.assertInKeychainUnmoved()
	})
	t.Run("enclave check canceled", func(t *testing.T) {
		w := newMoveWorld(t)
		w.startInKeychain()
		w.failStaged = canceled
		if err := w.mover().toEnclave(); !errors.Is(err, canceled) {
			t.Fatalf("got %v", err)
		}
		w.assertInKeychainUnmoved()
	})
	t.Run("enclave returns a different key", func(t *testing.T) {
		w := newMoveWorld(t)
		w.startInKeychain()
		w.lie = true
		if err := w.mover().toEnclave(); err == nil || !strings.Contains(err.Error(), "different key") {
			t.Fatalf("got %v", err)
		}
		w.assertInKeychainUnmoved()
	})
	t.Run("enclave dialog canceled on the way back", func(t *testing.T) {
		w := newMoveWorld(t)
		w.startInEnclave()
		w.failOpen = canceled
		if err := w.mover().toKeychain(); !errors.Is(err, canceled) {
			t.Fatalf("got %v", err)
		}
		if w.kc != nil || !exists(w.real()) || rekeyInProgress(w.root) {
			t.Fatalf("keychain %v, sealed %v, marker %v; want the enclave vault untouched", w.kc != nil, exists(w.real()), rekeyInProgress(w.root))
		}
	})
	t.Run("a different key already in the keychain", func(t *testing.T) {
		w := newMoveWorld(t)
		w.startInEnclave()
		w.kc = bytes.Repeat([]byte{7}, 32)
		if err := w.mover().toKeychain(); err == nil {
			t.Fatal("overwrote a different keychain key")
		}
		if !bytes.Equal(w.kc, bytes.Repeat([]byte{7}, 32)) || !exists(w.real()) || !w.enclaveKey {
			t.Fatal("the refusal changed something")
		}
	})
}

func (w *moveWorld) assertInKeychainUnmoved() {
	w.t.Helper()
	if !bytes.Equal(w.kc, w.mek) {
		w.t.Error("the keychain copy is gone after a move that failed early")
	}
	if exists(w.real()) {
		w.t.Error("a failed move left the vault looking like an enclave vault")
	}
	w.assertSettled()
}

func TestMoveWhenAlreadyThereDoesNothing(t *testing.T) {
	w := newMoveWorld(t)
	w.startInEnclave()
	if err := w.mover().toEnclave(); err != nil || len(w.prompts) != 0 {
		t.Fatalf("err=%v prompts=%q; want nothing asked", err, w.prompts)
	}
	w2 := newMoveWorld(t)
	w2.startInKeychain()
	if err := w2.mover().toKeychain(); err != nil || len(w2.prompts) != 0 {
		t.Fatalf("err=%v prompts=%q; want nothing asked", err, w2.prompts)
	}
}

// Decision D3: no move into the enclave without a recovery file newer than
// the newest secret.
func TestRecoveryFileCurrent(t *testing.T) {
	withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/API_KEY")
	if err := recoveryFileCurrent(root); err == nil || !strings.Contains(err.Error(), "jit vault export") {
		t.Fatalf("no export: %v, want a refusal naming jit vault export", err)
	}
	old := time.Now().Add(-time.Hour)
	if err := vault.RecordExport(root); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "last-export")
	if err := os.WriteFile(marker, []byte(old.UTC().Format(time.RFC3339)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoveryFileCurrent(root); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("stale export: %v, want a refusal saying it is older", err)
	}
	if err := vault.RecordExport(root); err != nil {
		t.Fatal(err)
	}
	if err := recoveryFileCurrent(root); err != nil {
		t.Fatalf("fresh export: %v", err)
	}
}

// The command's refusals, which all run before anything touches a key.
func TestVaultMoveRefusals(t *testing.T) {
	withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/API_KEY")
	stubKeyStores(t)
	vaultRekeyYes = true
	t.Cleanup(func() { vaultRekeyYes = false; vaultRekeyWrapper = "" })
	run := func(args ...string) error {
		vaultRekeyWrapper = ""
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetArgs(append([]string{"vault", "rekey"}, args...))
		return rootCmd.Execute()
	}
	if err := run("--wrapper", "tpm"); err == nil || !strings.Contains(err.Error(), "secure-enclave") {
		t.Errorf("an unknown target: %v", err)
	}
	if err := run("--wrapper", "secure-enclave"); err == nil || !strings.Contains(err.Error(), "recovery file") {
		t.Errorf("no recovery file: %v", err)
	}
	// A rotation's marker is not a move's to finish.
	if err := os.WriteFile(rekeyMarkerPath(root), []byte("started now\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("--wrapper", "keychain"); err == nil || !strings.Contains(err.Error(), "rotation") {
		t.Errorf("a move over a rotation marker: %v", err)
	}
	// A move's marker is not a rotation's, nor the other direction's.
	if err := os.WriteFile(rekeyMarkerPath(root), []byte("move secure-enclave started now\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), "--wrapper secure-enclave") {
		t.Errorf("a rotation over a move marker: %v", err)
	}
	if err := run("--wrapper", "keychain"); err == nil || !strings.Contains(err.Error(), "--wrapper secure-enclave") {
		t.Errorf("the other direction over a move marker: %v", err)
	}
}

// errOwnerEdit is what the keychain answered on the owner's Mac when the
// helper deleted a key an older jit had made (S3g).
var errOwnerEdit = errors.New("delete failed, OSStatus=-25244")

// The fail-safe: once the enclave copy is proven and promoted, a keychain
// copy that won't delete must not leave the vault refusing every change. The
// move finishes, the vault is an enclave vault, and it says a copy is left.
func TestMoveFinishesWhenTheKeychainCopyWontGo(t *testing.T) {
	w := newMoveWorld(t)
	w.startInKeychain()
	w.failDelete = errOwnerEdit
	if err := w.mover().toEnclave(); err != nil {
		t.Fatalf("the move failed over a keychain copy that wouldn't delete: %v", err)
	}
	if rekeyInProgress(w.root) {
		t.Fatal("the marker was left: every vault change would be refused")
	}
	if got, err := w.readSealed(w.real()); err != nil || !bytes.Equal(got, w.mek) {
		t.Fatalf("the vault's sealed file does not open to the MEK: %v", err)
	}
	if !bytes.Equal(w.kc, w.mek) {
		t.Fatal("the fake keychain copy changed")
	}
	out := w.out.String()
	if !strings.Contains(out, "keychain copy could not be deleted") ||
		!strings.Contains(out, "-25244") || !strings.Contains(out, "--wrapper secure-enclave") ||
		!strings.Contains(out, `"com.jitpass.vault.mek" in Keychain Access`) {
		t.Fatalf("output does not say a copy is left and how to remove it:\n%s", out)
	}
	// Not "never used again": an older jit still reads the keychain item.
	if !strings.Contains(out, "An older jit elsewhere on this Mac can still read it.") {
		t.Errorf("output does not say an older jit can still read the copy:\n%s", out)
	}
	assertShortLines(t, out)
	if !keychainCopyLeftWith(t, w.root, keystore.Present) {
		t.Fatal("status would not report the copy left behind")
	}
}

// The owner's Mac on 2026-09-25: the marker says "move secure-enclave", the
// sealed file is in place, the keychain copy is still there. Re-running the
// move finishes it with no dialog at all: the enclave copy was verified
// before the sealed file was renamed into place.
func TestMoveResumedAtTheKeychainDelete(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failDel   error
		wantKCGon bool
	}{
		{"the delete works now", nil, true},
		{"the delete still fails", errOwnerEdit, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newMoveWorld(t)
			w.startInEnclave()
			w.kc = append([]byte(nil), w.mek...)
			if err := w.mover().writeMarker(wrapperSecureEnclave); err != nil {
				t.Fatal(err)
			}
			w.failDelete = tc.failDel
			if err := w.mover().toEnclave(); err != nil {
				t.Fatalf("finishing the move: %v", err)
			}
			if len(w.prompts) != 0 {
				t.Errorf("prompts = %q, want none", w.prompts)
			}
			if rekeyInProgress(w.root) {
				t.Fatal("the marker survived")
			}
			if gone := w.kc == nil; gone != tc.wantKCGon {
				t.Fatalf("keychain copy gone = %v, want %v", gone, tc.wantKCGon)
			}
		})
	}
}

// `jit vault rekey --wrapper secure-enclave` on an enclave vault with a
// keychain copy removes the copy, and only once the enclave has opened and
// the copy has been found to be the same key.
func TestRemoveKeychainCopy(t *testing.T) {
	setup := func(t *testing.T) *moveWorld {
		w := newMoveWorld(t)
		w.startInEnclave()
		w.kc = append([]byte(nil), w.mek...)
		return w
	}
	t.Run("removed after one enclave dialog", func(t *testing.T) {
		w := setup(t)
		if err := w.mover().toEnclave(); err != nil {
			t.Fatal(err)
		}
		if w.kc != nil {
			t.Fatal("the keychain copy is still there")
		}
		if len(w.prompts) != 1 || w.prompts[0] != "enclave: "+reasonCopyGone {
			t.Errorf("prompts = %q, want only the enclave's %q", w.prompts, reasonCopyGone)
		}
		w.assertInEnclave()
	})
	t.Run("enclave dialog canceled", func(t *testing.T) {
		w := setup(t)
		w.failOpen = errors.New("canceled")
		if err := w.mover().toEnclave(); err == nil {
			t.Fatal("removed the copy without opening the enclave")
		}
		if !bytes.Equal(w.kc, w.mek) {
			t.Fatal("the copy went without the enclave's approval")
		}
	})
	t.Run("a different key under the vault key's name", func(t *testing.T) {
		w := setup(t)
		w.kc = bytes.Repeat([]byte{7}, 32)
		err := w.mover().toEnclave()
		if err == nil || !strings.Contains(err.Error(), "isn't this vault's") || !strings.Contains(err.Error(), "--wrapper secure-enclave --force") {
			t.Fatalf("got %v, want a refusal that names the --force form", err)
		}
		assertShortLines(t, err.Error())
		if !bytes.Equal(w.kc, bytes.Repeat([]byte{7}, 32)) {
			t.Fatal("deleted a key that is not the vault's")
		}
	})
	t.Run("an item that can't be read", func(t *testing.T) {
		w := setup(t)
		w.failMatch = errors.New("OSStatus=-25293")
		err := w.mover().toEnclave()
		if err == nil || !strings.Contains(err.Error(), "couldn't read") || !strings.Contains(err.Error(), "-25293") ||
			!strings.Contains(err.Error(), "Keychain Access") {
			t.Fatalf("got %v, want a refusal naming the read error and Keychain Access", err)
		}
		if !bytes.Equal(w.kc, w.mek) {
			t.Fatal("deleted an item it could not read")
		}
	})
	// --force resolves both when the item opens none of this vault's
	// secrets: it goes, and only once the enclave has opened in this run.
	for _, tc := range []struct {
		name      string
		kc        []byte
		failMatch error
	}{
		{"--force over a different key", bytes.Repeat([]byte{7}, 32), nil},
		{"--force over an unreadable item", nil, errors.New("OSStatus=-25293")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := setup(t)
			if tc.kc != nil {
				w.kc = tc.kc
			}
			w.failMatch = tc.failMatch
			if err := w.mover().toEnclaveAs(planRemoveCopy, true); err != nil {
				t.Fatal(err)
			}
			if w.kc != nil {
				t.Fatal("--force left the item")
			}
			if w.measured != 1 {
				t.Errorf("--force deleted after %d measures, want 1", w.measured)
			}
			if len(w.prompts) != 1 || w.prompts[0] != "enclave: "+reasonCopyGone {
				t.Errorf("prompts = %q, want only the enclave's", w.prompts)
			}
			w.assertInEnclave()
		})
	}
	// --force measures before it deletes: a key that opens any live secret
	// in this vault (an older jit may have saved them with it) is refused,
	// and so is one that can't be measured.
	t.Run("--force over a key that opens secrets here", func(t *testing.T) {
		w := setup(t)
		other := bytes.Repeat([]byte{7}, 32)
		w.kc = append([]byte(nil), other...)
		w.opens = 2
		err := w.mover().toEnclaveAs(planRemoveCopy, true)
		if err == nil || !strings.Contains(err.Error(), "it opens 2 secrets in this vault; jit won't delete it") {
			t.Fatalf("got %v, want a refusal naming how many secrets it opens", err)
		}
		assertShortLines(t, err.Error())
		if !bytes.Equal(w.kc, other) {
			t.Fatal("--force deleted a key that opens secrets in this vault")
		}
	})
	// Every live secret must have been tried: one whose envelope couldn't be
	// read is one the key may open. It used to count as "opens none", so a
	// vault whose envelopes couldn't be read had the key deleted on a
	// measure of nothing.
	t.Run("--force when some secrets couldn't be tested", func(t *testing.T) {
		w := setup(t)
		other := bytes.Repeat([]byte{7}, 32)
		w.kc = append([]byte(nil), other...)
		w.untested = 2
		err := w.mover().toEnclaveAs(planRemoveCopy, true)
		if err == nil || err.Error() != "jit couldn't test 2 secrets against that key; it was left alone" {
			t.Fatalf("got %v, want the untested refusal", err)
		}
		assertShortLines(t, err.Error())
		if !bytes.Equal(w.kc, other) {
			t.Fatal("--force deleted a key it couldn't test every secret against")
		}
	})
	t.Run("--force over a key that can't be measured", func(t *testing.T) {
		w := setup(t)
		w.failMatch = errors.New("OSStatus=-25308")
		w.failOpens = errors.New("OSStatus=-25308")
		err := w.mover().toEnclaveAs(planRemoveCopy, true)
		if err == nil || !strings.Contains(err.Error(), "couldn't check whether") || !strings.Contains(err.Error(), "Keychain Access") {
			t.Fatalf("got %v, want a refusal naming Keychain Access", err)
		}
		assertShortLines(t, err.Error())
		if w.kc == nil {
			t.Fatal("--force deleted a key it could not measure")
		}
	})
	t.Run("--force when the enclave won't open", func(t *testing.T) {
		w := setup(t)
		w.kc = bytes.Repeat([]byte{7}, 32)
		w.failOpen = errors.New("canceled")
		if err := w.mover().toEnclaveAs(planRemoveCopy, true); err == nil {
			t.Fatal("deleted the keychain item without the enclave opening")
		}
		if w.kc == nil {
			t.Fatal("the item went, and the enclave key is unproven: it may have been the only key")
		}
	})
	t.Run("the delete still fails", func(t *testing.T) {
		w := setup(t)
		w.failDelete = errOwnerEdit
		err := w.mover().toEnclave()
		if err == nil || !strings.Contains(err.Error(), "Keychain Access") {
			t.Fatalf("got %v, want the Keychain Access fallback", err)
		}
	})
	t.Run("no copy: nothing asked", func(t *testing.T) {
		w := newMoveWorld(t)
		w.startInEnclave()
		if err := w.mover().toEnclave(); err != nil || len(w.prompts) != 0 {
			t.Fatalf("err=%v prompts=%q", err, w.prompts)
		}
	})
}

// The recovery-file rule guards a move. Removing a copy moves nothing, so a
// stale (here: missing) recovery file must not stand in its way.
func TestVaultMoveRemovesACopyWithoutARecoveryFile(t *testing.T) {
	withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/API_KEY")
	stubKeyStores(t)
	w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32)}
	w.startInEnclave()
	w.kc = append([]byte(nil), w.mek...)
	orig := runMover
	runMover = func(string, io.Writer) *keyMover { return w.mover() }
	vaultRekeyYes = true
	t.Cleanup(func() { runMover = orig; vaultRekeyYes = false; vaultRekeyWrapper = "" })
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "rekey", "--wrapper", "secure-enclave"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault rekey --wrapper secure-enclave: %v", err)
	}
	if w.kc != nil {
		t.Fatal("the keychain copy is still there")
	}
}

// keychainCopyLeftWith runs status's check with the keychain answering p.
func keychainCopyLeftWith(t *testing.T, root string, p keystore.Presence) bool {
	t.Helper()
	orig := keychainCopyPresence
	keychainCopyPresence = func() keystore.Presence { return p }
	t.Cleanup(func() { keychainCopyPresence = orig })
	kind := keystore.KindKeychain
	if exists(filepath.Join(root, vault.SealedKeyFile)) {
		kind = keystore.KindSecureEnclave
	}
	return keychainCopyLeft(root, kind)
}

// Only a copy found counts, only in an enclave vault, and not while a move
// holds both copies on purpose.
func TestKeychainCopyLeft(t *testing.T) {
	w := newMoveWorld(t)
	if keychainCopyLeftWith(t, w.root, keystore.Present) {
		t.Error("a keychain vault's own key reported as a copy")
	}
	w.startInEnclave()
	if !keychainCopyLeftWith(t, w.root, keystore.Present) {
		t.Error("an enclave vault's keychain copy not reported")
	}
	for _, p := range []keystore.Presence{keystore.Absent, keystore.Indeterminate} {
		if keychainCopyLeftWith(t, w.root, p) {
			t.Errorf("reported a copy when the keychain answered %v", p)
		}
	}
	if err := w.mover().writeMarker(wrapperSecureEnclave); err != nil {
		t.Fatal(err)
	}
	if keychainCopyLeftWith(t, w.root, keystore.Present) {
		t.Error("reported a copy mid-move; move_unfinished says that")
	}
}

// assertShortLines holds new output to the house rule: one clause a line,
// about 72 characters.
func assertShortLines(t *testing.T, text string) {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if n := len([]rune(line)); n > 76 {
			t.Errorf("line of %d characters (house rule: about 72): %q", n, line)
		}
	}
}

// The prompt and the action come from ONE keychain check. Here the keychain
// says "there" when runVaultMove asks and "gone" after: the old code asked
// "Remove that copy?" and then answered "Nothing to do", from a second look.
func TestVaultMoveDecidesOnce(t *testing.T) {
	withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/API_KEY")
	stubKeyStores(t)
	w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32)}
	w.startInEnclave()
	w.kc = append([]byte(nil), w.mek...)
	w.presence = []keystore.Presence{keystore.Present, keystore.Absent}
	runVault := func(args ...string) (string, error) {
		orig := runMover
		m := w.mover()
		runMover = func(string, io.Writer) *keyMover { return m }
		t.Cleanup(func() { runMover = orig; vaultRekeyYes = false; vaultRekeyWrapper = ""; vaultRekeyForce = false })
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetIn(strings.NewReader("y\n"))
		rootCmd.SetArgs(args)
		err := rootCmd.Execute()
		return buf.String() + w.out.String(), err
	}
	out, err := runVault("vault", "rekey", "--wrapper", "secure-enclave")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "Remove it if it is the vault key?") {
		t.Fatalf("the question was not about removing the item:\n%s", out)
	}
	if strings.Contains(out, "Nothing to do") || w.kc != nil {
		t.Fatalf("the action did not follow the question (item gone: %v):\n%s", w.kc == nil, out)
	}
	if w.presenceCalls != 1 {
		t.Errorf("the keychain was checked %d times before acting, want once", w.presenceCalls)
	}
}

// A vault already in the enclave whose keychain would not answer: nothing is
// moved, so the recovery-file rule (here: no recovery file at all) must not
// stand in the way of saying so, and nothing is asked or deleted.
func TestVaultMoveIndeterminateKeychainIsNotAMove(t *testing.T) {
	withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/API_KEY")
	stubKeyStores(t)
	w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32)}
	w.startInEnclave()
	w.kc = append([]byte(nil), w.mek...)
	w.presence = []keystore.Presence{keystore.Indeterminate}
	orig := runMover
	runMover = func(string, io.Writer) *keyMover { return w.mover() }
	t.Cleanup(func() { runMover = orig; vaultRekeyWrapper = "" })
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetIn(strings.NewReader(""))
	rootCmd.SetArgs([]string{"vault", "rekey", "--wrapper", "secure-enclave"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "couldn't check your keychain") {
		t.Fatalf("got %v, want the keychain-couldn't-check answer\n%s", err, buf.String())
	}
	if strings.Contains(err.Error(), "recovery file") {
		t.Fatalf("the recovery-file rule was applied to a vault already in the enclave: %v", err)
	}
	if len(w.prompts) != 0 || w.kc == nil {
		t.Fatalf("prompts %q, item gone %v: want nothing asked or deleted", w.prompts, w.kc == nil)
	}
}

// --force goes only with a removal, and asks first, naming the risk.
func TestVaultMoveForce(t *testing.T) {
	withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/API_KEY")
	stubKeyStores(t)
	origTTY := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdinIsTerminal = origTTY })
	run := func(w *moveWorld, stdin string, args ...string) (string, error) {
		orig := runMover
		runMover = func(string, io.Writer) *keyMover { return w.mover() }
		t.Cleanup(func() { runMover = orig; vaultRekeyYes = false; vaultRekeyWrapper = ""; vaultRekeyForce = false })
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetIn(strings.NewReader(stdin))
		rootCmd.SetArgs(args)
		err := rootCmd.Execute()
		vaultRekeyYes, vaultRekeyWrapper, vaultRekeyForce = false, "", false
		return buf.String(), err
	}
	other := bytes.Repeat([]byte{7}, 32)

	w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32)}
	w.startInEnclave()
	w.kc = append([]byte(nil), other...)
	out, err := run(w, "n\n", "vault", "rekey", "--wrapper", "secure-enclave", "--force")
	if err != nil || !strings.Contains(out, "even if it isn't this vault's key") || !strings.Contains(out, "lost for good") {
		t.Fatalf("the --force question does not name the risk (err %v):\n%s", err, out)
	}
	assertShortLines(t, out)
	if !bytes.Equal(w.kc, other) || len(w.prompts) != 0 {
		t.Fatal("a no still deleted the item or asked the enclave")
	}
	if _, err := run(w, "y\n", "vault", "rekey", "--wrapper", "secure-enclave", "--force"); err != nil || w.kc != nil {
		t.Fatalf("--force with a yes: err %v, item gone %v", err, w.kc == nil)
	}

	// Nothing to remove: --force refuses rather than moving anything.
	if _, err := run(w, "y\n", "vault", "rekey", "--wrapper", "secure-enclave", "--force"); err == nil || !strings.Contains(err.Error(), "--force only removes") {
		t.Fatalf("--force with no item: %v", err)
	}
	if _, err := run(w, "y\n", "vault", "rekey", "--wrapper", "keychain", "--force"); err == nil || !strings.Contains(err.Error(), "--force only goes with") {
		t.Fatalf("--force with --wrapper keychain: %v", err)
	}
	// A keychain vault's own key is never a "copy": --force refuses there.
	k := &moveWorld{t: t, root: t.TempDir(), mek: bytes.Repeat([]byte{4}, 32)}
	k.startInKeychain()
	if _, err := run(k, "y\n", "vault", "rekey", "--wrapper", "secure-enclave", "--force"); err == nil || k.kc == nil {
		t.Fatalf("--force on a keychain vault: err %v, its key gone %v", err, k.kc == nil)
	}
}

// --force never runs on anything but a typed answer: not with --yes, and not
// where no one can answer (stdin not a terminal), whatever stdin holds.
// Before, `--force --yes` deleted the item with no question at all.
func TestVaultMoveForceNeedsATypedAnswer(t *testing.T) {
	withFixtureHome(t)
	root := seedFixtureVault(t, "fixture/API_KEY")
	stubKeyStores(t)
	origTTY := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = origTTY })
	other := bytes.Repeat([]byte{7}, 32)
	for _, tc := range []struct {
		name string
		tty  bool
		args []string
		want string
	}{
		{"--force --yes", true, []string{"--yes"}, "won't run with --yes"},
		{"--force with no terminal", false, nil, "no terminal here to ask in"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdinIsTerminal = func() bool { return tc.tty }
			w := &moveWorld{t: t, root: root, mek: bytes.Repeat([]byte{3}, 32)}
			w.startInEnclave()
			w.kc = append([]byte(nil), other...)
			orig := runMover
			runMover = func(string, io.Writer) *keyMover { return w.mover() }
			t.Cleanup(func() { runMover = orig; vaultRekeyYes = false; vaultRekeyWrapper = ""; vaultRekeyForce = false })
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)
			rootCmd.SetIn(strings.NewReader("y\n"))
			rootCmd.SetArgs(append([]string{"vault", "rekey", "--wrapper", "secure-enclave", "--force"}, tc.args...))
			err := rootCmd.Execute()
			vaultRekeyYes, vaultRekeyWrapper, vaultRekeyForce = false, "", false
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want a refusal saying %q\n%s", err, tc.want, buf.String())
			}
			assertShortLines(t, err.Error())
			if !bytes.Equal(w.kc, other) || len(w.prompts) != 0 || w.measured != 0 {
				t.Fatalf("item kept %v, prompts %q, measured %d: want nothing asked or deleted", bytes.Equal(w.kc, other), w.prompts, w.measured)
			}
		})
	}
}

// Key comparisons in the move are constant-time.
func TestMoveComparesKeysInConstantTime(t *testing.T) {
	// Beside this test file, not the working directory: scripts/se-test.sh
	// runs the test binary from the repository root.
	_, self, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(self), "vaultmove.go")
	f, err := parser.ParseFile(token.NewFileSet(), src, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "bytes" && sel.Sel.Name == "Equal" {
						t.Errorf("%s compares with bytes.Equal", fn.Name.Name)
					}
				}
			}
			return true
		})
	}
	if !strings.Contains(mustRead(t, src), "subtle.ConstantTimeCompare(got, mek) == 1") {
		t.Error("toEnclaveAs no longer checks the sealed copy with subtle.ConstantTimeCompare")
	}
}
