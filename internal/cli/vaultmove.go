// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

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
// for a vault with a sealed file. The copy is not harmless for all that: an
// older jit elsewhere on this Mac still reads the keychain item, as can any
// program running as the user, so the move says so. The copy left behind is
// not recorded anywhere: `jit status` (keychain_copy_left) and `jit doctor`
// (vault_key_copy) see it directly, an item under the vault key's name in an
// enclave vault, so the report can't go stale and also catches an item that
// got there some other way. `jit vault rekey --wrapper secure-enclave` on an
// enclave vault with such an item removes it when it is the same key, and
// with --force when it is not or can't be read (removeKeychainCopy).

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
	reasonCopyGone  = "remove a key under the vault key's name from your keychain"

	reasonVaultDelete = "permanently destroy the entire vault and its encryption key"
	reasonRekey       = "rotate the vault's master encryption key"
	reasonRekeyFinish = "finish rotating the vault's master encryption key"
)

// keyMover holds every operation a move performs, so a test drives the same
// sequence against fakes and can stop it after any step.
type keyMover struct {
	root string
	out  io.Writer

	kcPresent  func() keystore.Presence            // never prompts
	kcFetch    func(reason string) ([]byte, error) // the keychain's own Touch ID
	kcInstall  func(mek []byte) error              // writes and reads back; no prompt
	kcDelete   func() error
	kcMatches  func(mek []byte) (bool, error)      // reads with no prompt; returns no bytes
	kcReadable func() error                        // the quiet read alone (no prompt, no dialog); keeps nothing
	kcOpens    func() (keystore.KeyMeasure, error) // the item against every live secret; reads with no prompt or dialog

	seInstallStaged func(mek []byte) error              // seals; never prompts
	seOpenStaged    func(reason string) ([]byte, error) // the enclave's dialog
	sePromote       func() error                        // rename staged over real
	seRemoveStaged  func() error                        // drop an unverified staged file
	seOpen          func(reason string) ([]byte, error) // the enclave's dialog
	seDelete        func() error                        // the sealed file and the enclave key
	seReachable     func() error                        // this binary's entitlement: no keychain query, no prompt

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

// enclavePlan is what `jit vault rekey --wrapper secure-enclave` does,
// decided once by planToEnclave from ONE keychain check and then passed
// through, so the question runVaultMove asks and the action toEnclaveAs
// takes can never disagree, and a keychain that would not answer can never
// put the recovery-file rule (which guards a move) in front of a vault that
// is already in the enclave.
type enclavePlan int

const (
	planMove       enclavePlan = iota // the key is in the keychain: move it
	planResume                        // an interrupted move: finish it
	planRemoveCopy                    // in the enclave, a keychain item under its name: remove it
	planNothing                       // in the enclave, no keychain item
	planCantCheck                     // in the enclave, and the keychain would not say
)

// planToEnclave decides what a move into the enclave would do now.
func (m *keyMover) planToEnclave() enclavePlan {
	switch {
	case moveInProgress(m.root) == wrapperSecureEnclave:
		return planResume
	case !m.sealedExists():
		return planMove
	}
	switch m.kcPresent() {
	case keystore.Present:
		return planRemoveCopy
	case keystore.Absent:
		return planNothing
	}
	return planCantCheck
}

// toEnclave plans and runs a move into the enclave (tests, and callers with
// nothing to ask in between).
func (m *keyMover) toEnclave() error { return m.toEnclaveAs(m.planToEnclave(), false) }

// toEnclaveAs moves the MEK from the keychain into the Secure Enclave, or
// does what plan says instead. Two dialogs for a move: the keychain's (to
// read the key) and the enclave's (to prove the sealed copy opens before the
// keychain copy is deleted). force is removeKeychainCopy's.
func (m *keyMover) toEnclaveAs(plan enclavePlan, force bool) error {
	switch plan {
	case planRemoveCopy:
		return m.removeKeychainCopy(force)
	case planNothing:
		fmt.Fprintln(m.out, "The vault key is already in the Secure Enclave. Nothing to do.")
		return nil
	case planCantCheck:
		return errors.New("the vault key is already in the Secure Enclave,\n" +
			"but jit couldn't check your keychain for a key under its name.\n" +
			"Nothing changed; try again")
	}
	if err := m.writeMarker(wrapperSecureEnclave); err != nil {
		return err
	}
	m.lockAgent()

	// A real sealed file under a move marker was renamed into place only
	// after it was verified, so all that can be left is the keychain copy.
	// opened: the enclave copy opened in THIS run, which is what lets the
	// warning below name Keychain Access.
	opened := false
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
		same := subtle.ConstantTimeCompare(got, mek) == 1
		wipeBytes(got)
		if !same {
			return m.abort(errors.New("the Secure Enclave returned a different key; nothing changed, the key is still in the keychain"))
		}
		opened = true
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
		fmt.Fprint(m.out, hlCmds(copyLeftWarning(copyErr, m.kcReadable(), opened)))
	}
	return nil
}

// copyLeftWarning is what a move prints when it finished but the keychain
// copy would not go: one clause a line. The copy is not "never used again":
// an older jit elsewhere on this Mac still reads the keychain item, so the
// warning says so. The way on depends on why (readErr, the quiet read the
// move tried after the delete failed), because it must not be a jit
// command that fails the same way:
//
//   - the keychain may be locked (-25293): unlock it, then the command.
//   - this copy of jit isn't allowed to read it (-25308), or can't use it:
//     every quiet read from this jit fails the same way, so the command's
//     removal is no way out. Keychain Access is named, as the person's
//     choice, only when the enclave opened in this run (opened): then this
//     vault doesn't need the item. Otherwise the command, which opens the
//     enclave first and then names that way out itself.
//   - otherwise: the command, and Keychain Access as the person's choice
//     when the enclave opened in this run.
//
// It never says "delete".
func copyLeftWarning(err, readErr error, opened bool) string {
	head := fmt.Sprintf("The vault key's keychain copy could not be deleted.\n"+
		"The keychain said: %s\n"+
		"An older jit elsewhere on this Mac can still read it.\n", truncateEnd(err.Error(), 54))
	const retry = "`jit vault rekey --wrapper secure-enclave`"
	cause, detail := keychainReadCause(readErr)
	var why string
	switch cause {
	case readLocked:
		return head + fmt.Sprintf("Your keychain may be locked (%s). Unlock it,\n"+
			"then remove the copy with %s\n", detail, retry)
	case readNotAllowed:
		why = fmt.Sprintf("This copy of jit can't read it (%s).\n", detail)
	case readItem:
		why = fmt.Sprintf("jit can't use it (%s).\n", detail)
	}
	switch {
	case why != "" && opened:
		return head + why + removeItYourself("") + "\n"
	case why != "":
		return head + why + retry + " opens the vault key\n" +
			"in the Secure Enclave first, then says how that copy can go.\n"
	case opened:
		return head + "To remove it: " + retry + "\n" +
			fmt.Sprintf("Or remove it yourself in Keychain Access (%q).\n", keystore.KeychainItemName)
	}
	return head + "To remove it: " + retry + "\n"
}

// readCause is why a quiet read of the keychain item failed, as far as the
// way on differs.
type readCause int

const (
	readOK         readCause = iota // it was read
	readLocked                      // errSecAuthFailed: the keychain may be locked (measured)
	readNotAllowed                  // errSecInteractionNotAllowed: this copy of jit isn't allowed to read it
	readItem                        // the item itself: another refusal, or not a master key
	readOther                       // not about the item (the vault's own files, say)
)

// keychainReadCause sorts a quiet read's error (keychainwrap's
// QuietReadError, ErrNotAMasterKey) by what the person can do about it,
// with a short detail to show: the keychain's status, or what is wrong
// with the item.
func keychainReadCause(err error) (readCause, string) {
	var q *keychainwrap.QuietReadError
	switch {
	case err == nil:
		return readOK, ""
	case errors.As(err, &q) && q.MayBeLocked():
		return readLocked, fmt.Sprintf("OSStatus=%d", q.Status)
	case errors.As(err, &q) && q.NotAllowed():
		return readNotAllowed, fmt.Sprintf("OSStatus=%d", q.Status)
	case errors.As(err, &q):
		return readItem, fmt.Sprintf("OSStatus=%d", q.Status)
	case errors.Is(err, keychainwrap.ErrNotAMasterKey):
		return readItem, "it isn't a master key"
	}
	return readOther, truncateEnd(err.Error(), 40)
}

// removeItYourself is the way on from a refusal over a keychain item jit
// couldn't read or measure, once the vault key has opened from the Secure
// Enclave in this run: the vault doesn't need that item, but jit can't
// tell what else might, so removing it is the person's choice, never
// jit's advice. then, if set, is the command to run after.
func removeItYourself(then string) string {
	s := "The vault opens from the Secure Enclave and doesn't need that key;\n" +
		"jit can't tell whether anything else does. If nothing does,\n" +
		fmt.Sprintf("you can remove it yourself in Keychain Access (%q)", keystore.KeychainItemName)
	if then != "" {
		s += ",\nthen run " + then + " again"
	}
	return s
}

// removeKeychainCopy deletes the keychain item under the vault key's name
// from a vault whose key is already in the Secure Enclave: usually the copy
// a move whose last delete failed leaves behind. One dialog, the enclave's,
// always first: nothing goes unless the enclave copy opens in this run, so
// this can never delete the only key that works. Then:
//
//   - the item holds the same key: it is deleted.
//   - it holds a different key, or can't be read: without force it is left
//     alone, and the error says why and what to do, by cause: a locked
//     keychain is "unlock it and run this again"; an item this copy of jit
//     isn't allowed to read, or can't use, names Keychain Access as the
//     person's choice (the enclave opened, so this vault doesn't need it),
//     never --force, whose measure fails the same way. With force it is
//     measured first (kcOpens: how many of this vault's live secrets it
//     opens, read with no dialog): one that opens any is refused, since an
//     older jit may have saved those secrets with it, and one that can't be
//     measured is refused too. Only a key that opens none is deleted;
//     runVaultMove asked first, on a typed yes, naming the risk (whatever
//     that key protects elsewhere is lost).
//
// Changes nothing about where the vault opens from, so no marker.
func (m *keyMover) removeKeychainCopy(force bool) error {
	mek, err := m.seOpen(reasonCopyGone)
	if err != nil {
		return fmt.Errorf("opening the vault key in the Secure Enclave: %w (nothing changed)", err)
	}
	defer wipeBytes(mek)
	same, err := m.kcMatches(mek)
	switch {
	case err == nil && same:
	case force:
		if err := m.forceCheck(); err != nil {
			return err
		}
	case err != nil:
		return unreadableCopyRefusal(err)
	default:
		return errors.New("the key in your keychain under the vault key's name isn't this vault's.\n" +
			"It was left alone.\n" +
			"If nothing needs it: `jit vault rekey --wrapper secure-enclave --force`")
	}
	if err := m.kcDelete(); err != nil {
		// The enclave opened, and the item is the same key or --force
		// measured it as opening none of this vault's secrets.
		return fmt.Errorf("couldn't delete the key in your keychain: %s\n"+
			"You can remove it yourself in Keychain Access (%q)", truncateEnd(err.Error(), 54), keystore.KeychainItemName)
	}
	fmt.Fprintln(m.out, "Removed the key under the vault key's name from your keychain.")
	fmt.Fprintln(m.out, "The vault key is only in the Secure Enclave now.")
	return nil
}

// forceCheck is --force's measure before it deletes a key that isn't this
// vault's (or can't be matched): whether it opens any live secret here. It
// deletes only on a measure that covered everything: the item was read (a
// nil error from kcOpens says so), and every live secret was tried against
// it. A secret whose envelope couldn't be read is one the key may open, so
// even one refuses.
func (m *keyMover) forceCheck() error {
	got, err := m.kcOpens()
	switch {
	case err != nil:
		return unmeasuredCopyRefusal(err)
	case got.Opened > 0:
		return fmt.Errorf("the key in your keychain under the vault key's name isn't this vault's,\n"+
			"but it opens %s in this vault; jit won't delete it.\n"+
			"It was left alone: an older jit may have saved them with it", countWord(got.Opened, "secret", "secrets"))
	case got.Untested > 0:
		return fmt.Errorf("jit couldn't test %s against that key; it was left alone", countWord(got.Untested, "secret", "secrets"))
	}
	return nil
}

// unreadableCopyRefusal is removeKeychainCopy's refusal when the item
// couldn't be read to compare it, worded by the cause (keychainReadCause).
// The enclave has opened in this run.
func unreadableCopyRefusal(err error) error {
	const retry = "`jit vault rekey --wrapper secure-enclave`"
	cause, detail := keychainReadCause(err)
	switch cause {
	case readLocked:
		return fmt.Errorf("couldn't read the key in your keychain under the vault key's name\n"+
			"(%s): your keychain may be locked.\n"+
			"It was left alone. Unlock it, then run\n"+
			"%s again", detail, retry)
	case readNotAllowed:
		return fmt.Errorf("this copy of jit can't read the key in your keychain under the\n"+
			"vault key's name (%s); another copy of jit likely saved it.\n"+
			"It was left alone.\n%s", detail, removeItYourself(""))
	case readItem:
		return fmt.Errorf("couldn't use the key in your keychain under the vault key's name\n"+
			"(%s).\n"+
			"It was left alone.\n%s", detail, removeItYourself(""))
	}
	return fmt.Errorf("couldn't read the key in your keychain under the vault key's name\n"+
		"(%s).\n"+
		"It was left alone. Try %s again", detail, retry)
}

// unmeasuredCopyRefusal is forceCheck's refusal when the item couldn't be
// measured, worded by the cause (keychainReadCause). The enclave has
// opened in this run.
func unmeasuredCopyRefusal(err error) error {
	const retry = "`jit vault rekey --wrapper secure-enclave --force`"
	cause, detail := keychainReadCause(err)
	switch cause {
	case readLocked:
		return fmt.Errorf("jit couldn't check whether the key in your keychain\n"+
			"opens any of this vault's secrets (%s):\n"+
			"your keychain may be locked. It was left alone.\n"+
			"Unlock it, then run\n"+
			"%s again", detail, retry)
	case readNotAllowed:
		return fmt.Errorf("this copy of jit can't read the key in your keychain (%s),\n"+
			"so it couldn't check whether it opens any of this vault's secrets.\n"+
			"It was left alone.\n%s", detail, removeItYourself(""))
	case readItem:
		return fmt.Errorf("jit couldn't check whether the key in your keychain\n"+
			"opens any of this vault's secrets (%s).\n"+
			"It was left alone.\n%s", detail, removeItYourself(""))
	}
	return fmt.Errorf("jit couldn't check whether the key in your keychain\n"+
		"opens any of this vault's secrets (%s).\n"+
		"It was left alone. Try %s again", detail, retry)
}

// existingKeyRefusal is the move back to the keychain finding an item under
// the vault key's name that it couldn't read (keychainwrap's
// ErrExistingKeyUnreadable): it never writes over it, and says why by the
// cause. The enclave has opened in this run.
func existingKeyRefusal(err error) error {
	const retry = "`jit vault rekey --wrapper keychain`"
	const kept = "Nothing changed; the vault key is still in the Secure Enclave."
	cause, detail := keychainReadCause(err)
	switch cause {
	case readLocked:
		return fmt.Errorf("a key is already in your keychain under the vault key's name,\n"+
			"and jit couldn't read it (%s): your keychain may be locked.\n"+
			"%s\n"+
			"Unlock it, then run %s again", detail, kept, retry)
	case readNotAllowed:
		return fmt.Errorf("a key is already in your keychain under the vault key's name,\n"+
			"and this copy of jit can't read it (%s), so it won't\n"+
			"write over it; another copy of jit likely saved it.\n"+
			"%s\n%s", detail, kept, removeItYourself(retry))
	case readItem:
		return fmt.Errorf("a key is already in your keychain under the vault key's name,\n"+
			"and jit can't use it (%s), so it won't write over it.\n"+
			"%s\n%s", detail, kept, removeItYourself(retry))
	}
	return fmt.Errorf("a key is already in your keychain under the vault key's name,\n"+
		"and jit couldn't read it (%s), so it won't write over it.\n"+
		"%s Try %s again", detail, kept, retry)
}

// stdinIsTerminal reports whether a question can be answered here; a var so
// a test can say yes.
var stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

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
			if errors.Is(err, keychainwrap.ErrExistingKeyUnreadable) {
				return m.abort(existingKeyRefusal(err))
			}
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

// needsAppJitError refuses a command this copy of jit can't do because it
// can't reach the Secure Enclave (it isn't entitled: a jit outside
// JitPass.app). sealed says the vault's key is already there; command is
// what to run from the app instead; app finds the app's jit, only when this
// text is read and at most once (appJitLookup). With none found, or no
// app, the refusal names no path. The path is shell-quoted where it needs
// to be, so the command pastes as it reads.
type needsAppJitError struct {
	sealed  bool
	command string
	app     *appJitLookup
}

func (e needsAppJitError) Error() string {
	head := "only the jit inside JitPass.app can reach\nthe Secure Enclave; "
	if e.sealed {
		head = "this vault's key is in the Secure Enclave,\n" +
			"and only the jit inside JitPass.app can reach it; "
	}
	jit := e.app.jit()
	if jit == "" {
		return head + "use that jit to run:\n" + e.command
	}
	return head + "run it from there:\n`" + shellQuoteArg(jit) + " " + e.command + "`"
}

// checkReach is the move's first check, before the marker, the
// recovery-file rule, any question and any keychain access: a copy of jit
// that can't reach the Secure Enclave is told so at once. Every move into
// the enclave needs it (sealing, opening, or opening before removing a
// keychain copy), and a move back needs it whenever there is a sealed file
// or an unfinished move back; with neither, the key is already in the
// keychain and the move says so without the enclave. A sealed file jit
// can't check counts as there. Whether this jit can reach the enclave is
// its signature's entitlement (enclaveReach), not a keychain lookup, which
// a locked screen could fail for a jit that can.
func (m *keyMover) checkReach(target string) error {
	_, err := os.Lstat(m.sealedPath())
	sealed := !errors.Is(err, os.ErrNotExist)
	if target == wrapperKeychain && !sealed && moveInProgress(m.root) != wrapperKeychain {
		return nil
	}
	switch err := m.seReachable(); {
	case err == nil:
		return nil
	case errors.Is(err, secureenclave.ErrUnavailable):
		return needsAppJitError{sealed: sealed, command: "vault rekey --wrapper " + target, app: &appJitLookup{}}
	default:
		return fmt.Errorf("couldn't check whether this copy of jit can reach\n"+
			"the Secure Enclave (%v). Nothing changed", err)
	}
}

// runVaultMove is `jit vault rekey --wrapper <target>`.
func runVaultMove(cmd *cobra.Command, root, target string) error {
	out := cmd.OutOrStdout()
	if target != wrapperKeychain && target != wrapperSecureEnclave {
		return fmt.Errorf("jit vault rekey: --wrapper is %q or %q, not %q", wrapperSecureEnclave, wrapperKeychain, target)
	}
	m := runMover(root, out)
	if err := m.checkReach(target); err != nil {
		return fmt.Errorf("jit vault rekey: %w", err)
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
	if target == wrapperKeychain {
		if vaultRekeyForce {
			return errors.New("jit vault rekey: --force only goes with --wrapper secure-enclave")
		}
		if !vaultRekeyYes && !confirmPrompt(cmd, "Move the vault key back to the keychain? A program running as you could read it there again. [y/N] ") {
			fmt.Fprintln(out, "Aborted. Nothing was changed.")
			return nil
		}
		if err := m.toKeychain(); err != nil {
			return fmt.Errorf("jit vault rekey: %w", err)
		}
		return nil
	}
	// Decided once, from one keychain check: the question below and the
	// action after it follow the same plan (enclavePlan).
	plan := m.planToEnclave()
	if vaultRekeyForce && plan != planRemoveCopy {
		return errors.New("jit vault rekey: --force only removes a keychain key from a vault\n" +
			"already in the Secure Enclave, and there is none to remove")
	}
	// --force deletes a key that may protect something else, so it never
	// runs on anything but a person's typed answer to its question.
	if vaultRekeyForce && vaultRekeyYes {
		return errors.New("jit vault rekey: --force deletes a key only on your typed yes,\n" +
			"so it won't run with --yes")
	}
	if vaultRekeyForce && !stdinIsTerminal() {
		return errors.New("jit vault rekey: --force deletes a key only on your typed yes,\n" +
			"and there's no terminal here to ask in")
	}
	var prompt string
	switch plan {
	case planMove:
		// The recovery-file rule guards the move itself, and only the move:
		// removing a keychain item, or finding nothing to do, moves nothing.
		if err := recoveryFileCurrent(root); err != nil {
			return fmt.Errorf("jit vault rekey: %w", err)
		}
		prompt = "Move the vault key into the Secure Enclave? After this it can't leave this Mac; your recovery file is how the secrets would. [y/N] "
	case planResume:
		prompt = "A move of the vault key was interrupted. Finish it now? [y/N] "
	case planRemoveCopy:
		prompt = "A key is still in your keychain under the vault key's name.\n" +
			"Remove it if it is the vault key? [y/N] "
		if vaultRekeyForce {
			prompt = "A key is in your keychain under the vault key's name.\n" +
				"This deletes it even if it isn't this vault's key,\n" +
				"and whatever it protects is lost for good. Delete it? [y/N] "
		}
	}
	if prompt != "" && !vaultRekeyYes && !confirmPrompt(cmd, prompt) {
		fmt.Fprintln(out, "Aborted. Nothing was changed.")
		return nil
	}
	if err := m.toEnclaveAs(plan, vaultRekeyForce); err != nil {
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
		kcInstall:  kc.InstallMEK,
		kcDelete:   kc.DeleteMEK,
		kcMatches:  kc.MatchesMEK,
		kcReadable: kc.CheckQuietRead,
		kcOpens: func() (keystore.KeyMeasure, error) {
			return keystore.KeychainKeyOpens(root, kc)
		},
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
		seDelete:    func() error { return se().Delete() },
		seReachable: enclaveReach,
		lockAgent:   lock,
	}
}
