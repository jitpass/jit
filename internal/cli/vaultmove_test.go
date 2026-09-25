// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
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
	return &keyMover{
		root: w.root,
		out:  &bytes.Buffer{},
		kcPresent: func() keystore.Presence {
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
		kcDelete: func() error { w.kc = nil; return nil },
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
