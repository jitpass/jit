// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/secureenclave"
	"github.com/jitpass/jit/internal/vault"
)

// Moving a vault's master key between the login keychain and the Secure
// Enclave (`jit vault rekey --wrapper keychain|secure-enclave`,
// design/secure-enclave-plan.md step B4). The MEK itself never changes, so
// no envelope, grant or job is rewritten: only where the 32 bytes rest.
//
// The one rule every step keeps: at every instant, at least one place holds
// a copy of the MEK that is known to open. The old copy is deleted only
// after the new one has been read back and compared. A crash anywhere
// leaves the rekey marker, which makes every other vault command refuse,
// and re-running the same command finishes the move.

// moveMarkerPrefix marks rekey.inprogress as a MOVE, not a rotation: the
// two share the marker (so every command refuses mid-move the way it does
// mid-rotation) and must never finish each other's work.
const moveMarkerPrefix = "move "

const (
	wrapperKeychain      = "keychain"
	wrapperSecureEnclave = "secure-enclave"
)

// moveInProgress returns the target of an interrupted move, or "" when the
// marker is absent or belongs to a rotation.
func moveInProgress(root string) string {
	data, err := os.ReadFile(rekeyMarkerPath(root)) // #nosec G304 -- the vault root's own marker
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if !strings.HasPrefix(line, moveMarkerPrefix) {
		return ""
	}
	return strings.Fields(strings.TrimPrefix(line, moveMarkerPrefix))[0]
}

// The move's dialog reasons, shown after the app's name ("JitPass is trying
// to move the vault key into the Secure Enclave.").
const (
	reasonMoveIn    = "move the vault key into the Secure Enclave"
	reasonMoveCheck = "check the vault key in the Secure Enclave"
	reasonMoveBack  = "move the vault key back to the keychain"

	reasonVaultDelete = "permanently destroy the entire vault and its encryption key"
	reasonRekey       = "rotate the vault's master encryption key"
	reasonRekeyFinish = "finish rotating the vault's master encryption key"
)

// keyMover holds every operation a move performs, so a test drives the same
// sequence against fakes and can stop it after any step.
type keyMover struct {
	root string
	out  io.Writer

	kcPresent func() keystore.Presence            // never prompts
	kcFetch   func(reason string) ([]byte, error) // the keychain's own Touch ID
	kcInstall func(mek []byte) error              // writes and reads back; no prompt
	kcDelete  func() error

	seInstallStaged func(mek []byte) error              // seals; never prompts
	seOpenStaged    func(reason string) ([]byte, error) // the enclave's dialog
	sePromote       func() error                        // rename staged over real
	seRemoveStaged  func() error                        // drop an unverified staged file
	seOpen          func(reason string) ([]byte, error) // the enclave's dialog
	seDelete        func() error                        // the sealed file and the enclave key

	lockAgent func()

	// crash, when set, runs after each named step; an error stops the move
	// there, as a crash would. Tests only.
	crash func(step string) error
}

// errCrashed wraps what a test's crash hook returns, so abort can tell an
// injected crash (which must leave everything as a real crash would) from a
// failure the move itself handles.
type errCrashed struct{ err error }

func (e errCrashed) Error() string { return e.err.Error() }

func (m *keyMover) step(name string) error {
	if m.crash == nil {
		return nil
	}
	if err := m.crash(name); err != nil {
		return errCrashed{err}
	}
	return nil
}

// abort undoes a move that failed before its new copy existed: nothing
// about the vault changed, so the staged file and the marker go, and the
// vault is usable again at once instead of refusing every command until a
// re-run. A crash (real or injected) never reaches here.
func (m *keyMover) abort(err error) error {
	if errors.As(err, &errCrashed{}) {
		return err
	}
	_ = m.seRemoveStaged()
	_ = os.Remove(rekeyMarkerPath(m.root))
	return err
}

func (m *keyMover) sealedPath() string { return filepath.Join(m.root, vault.SealedKeyFile) }

func (m *keyMover) sealedExists() bool {
	_, err := os.Lstat(m.sealedPath())
	return err == nil
}

func (m *keyMover) writeMarker(target string) error {
	return vault.AtomicWriteFile(rekeyMarkerPath(m.root),
		fmt.Appendf(nil, "%s%s started %s\n", moveMarkerPrefix, target, time.Now().Format(time.RFC3339)))
}

func (m *keyMover) finish() error {
	m.lockAgent()
	if err := os.Remove(rekeyMarkerPath(m.root)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing the marker: %w", err)
	}
	return nil
}

// toEnclave moves the MEK from the keychain into the Secure Enclave. Two
// dialogs: the keychain's (to read the key) and the enclave's (to prove the
// sealed copy opens before the keychain copy is deleted).
func (m *keyMover) toEnclave() error {
	resumed := moveInProgress(m.root) == wrapperSecureEnclave
	if !resumed && m.sealedExists() {
		fmt.Fprintln(m.out, "The vault key is already in the Secure Enclave. Nothing to do.")
		return nil
	}
	if err := m.writeMarker(wrapperSecureEnclave); err != nil {
		return err
	}
	m.lockAgent()

	// A real sealed file under a move marker was renamed into place only
	// after it was verified, so all that can be left is the keychain copy.
	if !m.sealedExists() {
		// A staged file from an interrupted run was never verified; start
		// that half again rather than trust it.
		if err := m.seRemoveStaged(); err != nil {
			return m.abort(err)
		}
		mek, err := m.kcFetch(reasonMoveIn)
		if err != nil {
			return m.abort(err)
		}
		defer wipeBytes(mek)
		if err := m.seInstallStaged(mek); err != nil {
			return m.abort(fmt.Errorf("sealing the key to the Secure Enclave: %w (nothing changed)", err))
		}
		if err := m.step("staged"); err != nil {
			return m.abort(err)
		}
		got, err := m.seOpenStaged(reasonMoveCheck)
		if err != nil {
			return m.abort(fmt.Errorf("checking the sealed key: %w (nothing changed, the key is still in the keychain)", err))
		}
		same := bytes.Equal(got, mek)
		wipeBytes(got)
		if !same {
			return m.abort(errors.New("the Secure Enclave returned a different key; nothing changed, the key is still in the keychain"))
		}
		if err := m.step("verified"); err != nil {
			return m.abort(err)
		}
		if err := m.sePromote(); err != nil {
			return err
		}
		if err := m.step("promoted"); err != nil {
			return err
		}
	}

	if m.kcPresent() != keystore.Absent {
		if err := m.kcDelete(); err != nil {
			return fmt.Errorf("the key is in the Secure Enclave, but its old keychain copy could not be deleted: %w (re-run to finish)", err)
		}
	}
	if err := m.step("keychain deleted"); err != nil {
		return err
	}
	if err := m.finish(); err != nil {
		return err
	}
	fmt.Fprintln(m.out, "Moved the vault key into the Secure Enclave. Every secret opens as before.")
	return nil
}

// toKeychain moves the MEK from the Secure Enclave back into the keychain.
// One dialog: the enclave's, to read the key. The keychain copy is read
// back and compared before the sealed file and the enclave key go.
func (m *keyMover) toKeychain() error {
	resumed := moveInProgress(m.root) == wrapperKeychain
	if !resumed && !m.sealedExists() {
		fmt.Fprintln(m.out, "The vault key is already in the keychain. Nothing to do.")
		return nil
	}
	if err := m.writeMarker(wrapperKeychain); err != nil {
		return err
	}
	m.lockAgent()

	if m.sealedExists() {
		mek, err := m.seOpen(reasonMoveBack)
		if err != nil {
			return m.abort(err)
		}
		defer wipeBytes(mek)
		if err := m.kcInstall(mek); err != nil {
			return m.abort(fmt.Errorf("writing the key to the keychain: %w (nothing changed, the key is still in the Secure Enclave)", err))
		}
		if err := m.step("installed"); err != nil {
			return err
		}
		// From this removal on, keystore.Open sees a keychain vault.
		if err := os.Remove(m.sealedPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing the sealed key file: %w", err)
		}
		if err := m.step("file removed"); err != nil {
			return err
		}
	}
	if err := m.seDelete(); err != nil {
		return fmt.Errorf("the key is in the keychain, but the old Secure Enclave key could not be deleted: %w (re-run to finish)", err)
	}
	if err := m.step("enclave deleted"); err != nil {
		return err
	}
	if err := m.finish(); err != nil {
		return err
	}
	fmt.Fprintln(m.out, "Moved the vault key back to the keychain. Every secret opens as before.")
	return nil
}

// recoveryFileCurrent is decision D3: a vault moves into the enclave only
// with a recovery file newer than its newest secret, because afterwards the
// key cannot follow it to another Mac.
func recoveryFileCurrent(root string) error {
	exportedAt, recorded, err := vault.LastExport(root)
	if err != nil {
		return fmt.Errorf("checking for a recovery file: %w", err)
	}
	if !recorded {
		return errors.New("save a recovery file first with `jit vault export`: once the key is in the Secure Enclave it can't move to another Mac, and that file is how the secrets would")
	}
	newest, err := (&vault.Vault{Root: root}).NewestSecretTime()
	if err != nil {
		return fmt.Errorf("checking for a recovery file: %w", err)
	}
	if newest.After(exportedAt) {
		return errors.New("your recovery file is older than your newest secret; save a new one with `jit vault export` first")
	}
	return nil
}

// runVaultMove is `jit vault rekey --wrapper <target>`.
func runVaultMove(cmd *cobra.Command, root, target string) error {
	out := cmd.OutOrStdout()
	if target != wrapperKeychain && target != wrapperSecureEnclave {
		return fmt.Errorf("jit vault rekey: --wrapper is %q or %q, not %q", wrapperSecureEnclave, wrapperKeychain, target)
	}
	// A rotation's marker must be finished by `jit vault rekey`, not
	// adopted by a move.
	if rekeyInProgress(root) && moveInProgress(root) == "" {
		return errors.New("jit vault rekey: a rotation of the master key is unfinished; run `jit vault rekey` to finish it first")
	}
	if other := moveInProgress(root); other != "" && other != target {
		return fmt.Errorf("jit vault rekey: a move to %s is unfinished; run `jit vault rekey --wrapper %s` to finish it first", other, other)
	}
	resuming := moveInProgress(root) == target
	if target == wrapperSecureEnclave && !resuming {
		if err := recoveryFileCurrent(root); err != nil {
			return fmt.Errorf("jit vault rekey: %w", err)
		}
	}
	if !vaultRekeyYes {
		prompt := "Move the vault key into the Secure Enclave? After this it can't leave this Mac; your recovery file is how the secrets would. [y/N] "
		if target == wrapperKeychain {
			prompt = "Move the vault key back to the keychain? A program running as you could read it there again. [y/N] "
		}
		if resuming {
			prompt = "A move of the vault key was interrupted. Finish it now? [y/N] "
		}
		if !confirmPrompt(cmd, prompt) {
			fmt.Fprintln(out, "Aborted. Nothing was changed.")
			return nil
		}
	}
	m := newKeyMover(root, out)
	var err error
	if target == wrapperSecureEnclave {
		err = m.toEnclave()
	} else {
		err = m.toKeychain()
	}
	if err != nil {
		return fmt.Errorf("jit vault rekey: %w", err)
	}
	return nil
}

// newKeyMover wires the production operations: the vault's own keychain
// item and enclave key.
func newKeyMover(root string, out io.Writer) *keyMover {
	return newKeyMoverWith(root, out, keystore.Keychain(),
		func() *secureenclave.Wrapper { return secureenclave.New(root) },
		func() *secureenclave.Wrapper { return secureenclave.NewStaged(root) },
		lockAgent)
}

// newKeyMoverWith wires a mover to a keychain Wrapper and enclave Wrapper
// constructors: production passes the vault's own, the hardware test passes
// TEST-ONLY ones. Each enclave use gets a fresh Wrapper, closed after, so no
// MEK stays cached in one.
func newKeyMoverWith(root string, out io.Writer, kc *keychainwrap.Wrapper, se, seStaged func() *secureenclave.Wrapper, lock func()) *keyMover {
	return &keyMover{
		root: root,
		out:  out,
		kcPresent: func() keystore.Presence {
			switch kc.MEKPresence() {
			case keychainwrap.MEKPresent:
				return keystore.Present
			case keychainwrap.MEKAbsent:
				return keystore.Absent
			}
			return keystore.Indeterminate
		},
		kcFetch: func(reason string) ([]byte, error) {
			// The copy returned is the mover's; the wrapper's own cache goes.
			defer kc.Close()
			return kc.FetchMEK(reason)
		},
		kcInstall:       kc.InstallMEK,
		kcDelete:        kc.DeleteMEK,
		seInstallStaged: func(mek []byte) error { return seStaged().Install(mek) },
		seOpenStaged: func(reason string) ([]byte, error) {
			w := seStaged()
			defer w.Close()
			return w.FetchMEK(reason)
		},
		sePromote:      func() error { return secureenclave.PromoteStaged(root) },
		seRemoveStaged: func() error { return secureenclave.RemoveStaged(root) },
		seOpen: func(reason string) ([]byte, error) {
			w := se()
			defer w.Close()
			return w.FetchMEK(reason)
		},
		seDelete:  func() error { return se().Delete() },
		lockAgent: lock,
	}
}
