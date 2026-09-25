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
//
// One step may not complete and still not block the vault: deleting the
// keychain copy once the enclave copy is proven. An older jit's keychain item
// once refused the delete (errSecInvalidOwnerEdit, S3g in
// spike/secure-enclave-mek/FINDINGS.md; keychainwrap now removes it another
// way). If a delete still fails, the move finishes anyway, because the vault
// already opens from the enclave and keystore.Open never reads the keychain
// for a vault with a sealed file. The copy left behind is not recorded
// anywhere: `jit status` (keychain_copy_left) and `jit doctor`
// (vault_key_copy) see it directly, an item under the vault key's name in an
// enclave vault, so the report can't go stale and also catches a copy that
// got there some other way. `jit vault rekey --wrapper secure-enclave` on an
// enclave vault with such a copy removes it (removeKeychainCopy).

// moveMarkerPrefix marks rekey.inprogress as a MOVE, not a rotation: the
// two share the marker (so every command refuses mid-move the way it does
// mid-rotation) and must never finish each other's work.
const moveMarkerPrefix = "move "

const (
	wrapperKeychain      = "keychain"
	wrapperSecureEnclave = "secure-enclave"
)

// markerKind is what the rekey marker says, read without trusting more of
// it than jit can prove.
type markerKind int

const (
	markerNone      markerKind = iota // no marker: the vault is open for changes
	markerRotation                    // a rotation's own "started …" line
	markerMove                        // a move to a target this jit knows
	markerOtherMove                   // a move to a target this jit does not know
	markerUnknown                     // a marker jit can't read, or doesn't recognise
)

// rekeyMarker is the marker's reading. target is set for either kind of
// move; err for a marker that is there but could not be read.
type rekeyMarker struct {
	kind   markerKind
	target string
	err    error
}

// readRekeyMarker reads rekey.inprogress. Only a line jit itself writes
// counts as a rotation's ("started …", vaultrekey.go) or a move's
// ("move <target> started …", writeMarker); anything else is markerUnknown,
// which no command will finish, because none can prove what it would be
// finishing.
func readRekeyMarker(root string) rekeyMarker {
	data, err := os.ReadFile(rekeyMarkerPath(root)) // #nosec G304 -- the vault root's own marker
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rekeyMarker{kind: markerNone}
		}
		return rekeyMarker{kind: markerUnknown, err: err}
	}
	line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if rest, ok := strings.CutPrefix(line, moveMarkerPrefix); ok {
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return rekeyMarker{kind: markerUnknown}
		}
		switch fields[0] {
		case wrapperSecureEnclave, wrapperKeychain:
			return rekeyMarker{kind: markerMove, target: fields[0]}
		}
		return rekeyMarker{kind: markerOtherMove, target: fields[0]}
	}
	if line == "started" || strings.HasPrefix(line, "started ") {
		return rekeyMarker{kind: markerRotation}
	}
	return rekeyMarker{kind: markerUnknown}
}

// moveInProgress returns the target of an interrupted move, known or not,
// or "" when the marker is absent, belongs to a rotation, or can't be read.
func moveInProgress(root string) string {
	if m := readRekeyMarker(root); m.kind == markerMove || m.kind == markerOtherMove {
		return m.target
	}
	return ""
}

// moveUnfinished is moveInProgress for REPORTING (`jit status`
// move_unfinished, doctor's vault_move): the target only when it is one this
// jit knows, else "". A marker it cannot read or does not recognise gets its
// own report (unknownMarkerDetail); the commands themselves keep refusing
// on the marker's mere presence (rekeyInProgress), so nothing here loosens
// that.
func moveUnfinished(root string) string {
	if m := readRekeyMarker(root); m.kind == markerMove {
		return m.target
	}
	return ""
}

// moveDescription is what an unfinished move to target was doing, in the
// reader's words.
func moveDescription(target string) string {
	if target == wrapperKeychain {
		return "moving the vault key back to your keychain"
	}
	return "moving the vault key into the Secure Enclave"
}

// unknownMarkerDetail is what jit can honestly say about a marker it can't
// finish: one it can't read, or a change it doesn't recognise (a move to a
// target a newer jit wrote, or a line no jit writes). Neither `jit vault
// rekey` nor any `--wrapper` can finish it: the rotation would resume over
// a half-done move, and a move needs a target this jit knows.
func unknownMarkerDetail(m rekeyMarker) string {
	switch {
	case m.err != nil:
		return fmt.Sprintf("jit can't read the file that marks an unfinished change of the vault key (%v), so every command that changes the vault will refuse until it can.", m.err)
	case m.kind == markerOtherMove:
		return fmt.Sprintf("a move of the vault key this version of jit doesn't understand (to %q) is unfinished, so every command that changes the vault will refuse until it finishes.", m.target)
	}
	return "a change of the vault key this version of jit doesn't understand is unfinished, so every command that changes the vault will refuse until it finishes."
}

// unknownMarkerAction is the step for unknownMarkerDetail. Plain words, no
// command: there is no jit command here that would work.
func unknownMarkerAction(m rekeyMarker) string {
	if m.err != nil {
		return "make that file readable again, then check again"
	}
	return "update jit, then finish it with the newer jit"
}

// rekeyMarkerRefusal is what a vault command reports while the marker
// exists. A move's own sentence names the command that finishes it:
// errRekeyInProgress sends the reader to `jit vault rekey`, which refuses
// to finish a move, and a marker jit can't read or doesn't recognise names
// no command at all, since none would work.
func rekeyMarkerRefusal(root string) error {
	switch m := readRekeyMarker(root); m.kind {
	case markerMove:
		return fmt.Errorf("%s did not finish, and vault changes are refused until it does; run `jit vault rekey --wrapper %s` to finish it", moveDescription(m.target), m.target)
	case markerOtherMove, markerUnknown:
		return errors.New(unknownMarkerDetail(m) + " To fix: " + unknownMarkerAction(m) + ".")
	}
	return errRekeyInProgress
}

// The move's dialog reasons, shown after the app's name ("JitPass is trying
// to move the vault key into the Secure Enclave.").
const (
	reasonMoveIn    = "move the vault key into the Secure Enclave"
	reasonMoveCheck = "check the vault key in the Secure Enclave"
	reasonMoveBack  = "move the vault key back to the keychain"
	reasonCopyGone  = "remove the old copy of the vault key from your keychain"

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
	kcMatches func(mek []byte) (bool, error) // reads with no prompt; returns no bytes

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
		if m.kcPresent() == keystore.Present {
			return m.removeKeychainCopy()
		}
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

	// From here the vault opens from the enclave (keystore.Open follows the
	// sealed file), so a keychain copy that won't go must not keep the
	// vault refusing changes: the move finishes, and says so.
	var copyErr error
	if m.kcPresent() != keystore.Absent {
		copyErr = m.kcDelete()
	}
	if err := m.step("keychain deleted"); err != nil {
		return err
	}
	if err := m.finish(); err != nil {
		return err
	}
	fmt.Fprintln(m.out, "Moved the vault key into the Secure Enclave. Every secret opens as before.")
	if copyErr != nil {
		fmt.Fprintln(m.out, hlCmds(copyLeftWarning(copyErr)))
	}
	return nil
}

// copyLeftWarning is what the move, and the removal, print when the old
// keychain copy would not go. The Keychain Access step is there for the day
// no API removes it: then a person can.
func copyLeftWarning(err error) string {
	return fmt.Sprintf("An old copy of the vault key is still in your keychain; jit couldn't delete it (%v). "+
		"Run `jit vault rekey --wrapper secure-enclave` to try again, or delete %q in Keychain Access.", err, keychainItemName)
}

// keychainItemName is the vault key item's name as Keychain Access lists it.
const keychainItemName = "com.jitpass.vault.mek"

// removeKeychainCopy deletes a keychain copy of the vault key from a vault
// whose key is already in the Secure Enclave: what a move whose last delete
// failed leaves behind. One dialog, the enclave's: the copy goes only once
// the enclave copy has opened in this run and the keychain copy has been
// read and found to be the same key, so it can never delete the only key
// that works. A keychain item that holds a different key is left alone.
// Changes nothing about where the vault opens from, so no marker.
func (m *keyMover) removeKeychainCopy() error {
	mek, err := m.seOpen(reasonCopyGone)
	if err != nil {
		return fmt.Errorf("opening the vault key in the Secure Enclave: %w (nothing changed)", err)
	}
	defer wipeBytes(mek)
	same, err := m.kcMatches(mek)
	if err != nil {
		return fmt.Errorf("reading the keychain copy: %w (nothing changed)", err)
	}
	if !same {
		return fmt.Errorf("the keychain item %q holds a different key from the one in the Secure Enclave, so jit left it alone; delete it in Keychain Access if you know it isn't needed", keychainItemName)
	}
	if err := m.kcDelete(); err != nil {
		return errors.New(copyLeftWarning(err))
	}
	fmt.Fprintln(m.out, "Removed the old copy of the vault key from your keychain. The key is only in the Secure Enclave now.")
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
	// adopted by a move; a marker jit can't read or doesn't recognise is
	// finished by nothing here.
	marker := readRekeyMarker(root)
	switch marker.kind {
	case markerRotation:
		return errors.New("jit vault rekey: a rotation of the master key is unfinished; run `jit vault rekey` to finish it first")
	case markerOtherMove, markerUnknown:
		return fmt.Errorf("jit vault rekey: %w", rekeyMarkerRefusal(root))
	case markerMove:
		if marker.target != target {
			return fmt.Errorf("jit vault rekey: a move to %s is unfinished; run `jit vault rekey --wrapper %s` to finish it first", marker.target, marker.target)
		}
	}
	resuming := marker.kind == markerMove && marker.target == target
	m := runMover(root, out)
	// Already in the enclave, with the keychain copy a move could not delete
	// still there: this run removes that copy and moves nothing, so the
	// recovery-file rule (which guards the move itself) does not apply.
	copyOnly := target == wrapperSecureEnclave && !resuming && m.sealedExists() && m.kcPresent() == keystore.Present
	if target == wrapperSecureEnclave && !resuming && !copyOnly {
		if err := recoveryFileCurrent(root); err != nil {
			return fmt.Errorf("jit vault rekey: %w", err)
		}
	}
	if !vaultRekeyYes {
		prompt := "Move the vault key into the Secure Enclave? After this it can't leave this Mac; your recovery file is how the secrets would. [y/N] "
		switch {
		case resuming:
			prompt = "A move of the vault key was interrupted. Finish it now? [y/N] "
		case copyOnly:
			prompt = "The vault key is in the Secure Enclave, and an old copy is still in your keychain. Remove that copy? [y/N] "
		case target == wrapperKeychain:
			prompt = "Move the vault key back to the keychain? A program running as you could read it there again. [y/N] "
		}
		if !confirmPrompt(cmd, prompt) {
			fmt.Fprintln(out, "Aborted. Nothing was changed.")
			return nil
		}
	}
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

// runMover is the mover runVaultMove drives: newKeyMover, a var so a test
// runs the command against the in-memory keychain and enclave.
var runMover = newKeyMover

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
		kcMatches:       kc.MatchesMEK,
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
