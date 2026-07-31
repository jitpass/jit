// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package pasteboard

import (
	"fmt"
	"os"
	"testing"
)

// Every test here runs against a private NAMED pasteboard, never the general
// one. That is not tidiness: the general pasteboard is the machine's real
// clipboard, so a test that wrote to it would destroy whatever the person
// running the suite had just copied, and clearIfUnchanged would be deleting
// their data rather than jit's secret. Same rule, same reason as
// internal/keychainwrap's TEST-ONLY service name and internal/screenlock's
// jit-namespaced notification.
//
// The name carries the pid so two packages' test binaries running concurrently
// (go test ./... runs packages in parallel) can never share a board.
func testBoard(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("com.jitpass.test.pasteboard.%d.%s", os.Getpid(), t.Name())
	t.Cleanup(func() {
		// Leave nothing behind on a board that outlives the process: clear
		// unconditionally, which is safe precisely because this board is ours.
		clearIfUnchanged(name, changeCount(name))
	})
	return name
}

// TestWriteConcealedDeclaresTheConcealedType is the one that matters most.
// org.nspasteboard.ConcealedType is the entire mechanism keeping a copied
// secret out of every clipboard manager's searchable history — the exposure
// this package exists to close. Nothing about a dropped declaration is
// visible: the copy still works, the secret still pastes, and it is silently
// indexed forever. So the marker's presence is pinned here rather than
// trusted.
func TestWriteConcealedDeclaresTheConcealedType(t *testing.T) {
	board := testBoard(t)
	if _, err := writeConcealed(board, []byte("sk_live_secret_value")); err != nil {
		t.Fatalf("writeConcealed: %v", err)
	}
	if !hasType(board, concealedType) {
		t.Errorf("the write did not declare %s; every secret copied through jit would be recorded in clipboard-manager history", concealedType)
	}
	// The text type must be there too, or the secret never reaches the paste.
	if !hasType(board, "public.utf8-plain-text") {
		t.Error("the write declared no plain-text type, so nothing could paste it")
	}
}

// The returned changeCount is the handle the whole clear-later contract rests
// on, so it has to be this write's count — not a stale one, and not zero.
func TestWriteConcealedReturnsThisWritesChangeCount(t *testing.T) {
	board := testBoard(t)
	count, err := writeConcealed(board, []byte("first"))
	if err != nil {
		t.Fatalf("writeConcealed: %v", err)
	}
	if got := changeCount(board); got != count {
		t.Errorf("WriteConcealed returned %d but the board reports %d", count, got)
	}

	// A second write must produce a DIFFERENT handle, or the first write's
	// handle would still authorize clearing the second write's contents.
	second, err := writeConcealed(board, []byte("second"))
	if err != nil {
		t.Fatalf("writeConcealed (second): %v", err)
	}
	if second == count {
		t.Errorf("two writes reported the same changeCount %d; the handle cannot distinguish them", count)
	}
}

// The happy path of the hygiene mechanism: jit copied it, nothing else has
// been copied since, so the scheduled clear takes it away.
func TestClearIfUnchangedClearsOurOwnCopy(t *testing.T) {
	board := testBoard(t)
	count, err := writeConcealed(board, []byte("sk_live_secret_value"))
	if err != nil {
		t.Fatalf("writeConcealed: %v", err)
	}
	if !clearIfUnchanged(board, count) {
		t.Fatal("clearIfUnchanged refused to clear a board nothing else had touched, so a copied secret would sit there indefinitely")
	}
	// clearContents drops the declared types along with the value.
	if hasType(board, concealedType) {
		t.Error("the board still declares the concealed type after a clear, so it was not actually cleared")
	}
}

// TestClearIfUnchangedRefusesAfterANewerCopy is the data-loss guard, and the
// reason the mechanism keys on changeCount instead of just clearing on a
// timer. Between jit's copy and the scheduled clear, the user copies something
// of their own — an address, a paragraph they are moving. Clearing then would
// destroy the user's work to tidy up jit's secret, which is a straight
// downgrade on doing nothing at all.
func TestClearIfUnchangedRefusesAfterANewerCopy(t *testing.T) {
	board := testBoard(t)
	ours, err := writeConcealed(board, []byte("sk_live_secret_value"))
	if err != nil {
		t.Fatalf("writeConcealed: %v", err)
	}
	// The user copies something afterwards.
	theirs, err := writeConcealed(board, []byte("something the user copied"))
	if err != nil {
		t.Fatalf("writeConcealed (user's copy): %v", err)
	}

	if clearIfUnchanged(board, ours) {
		t.Fatal("clearIfUnchanged cleared the board on a stale handle; jit's cleanup would delete whatever the user copied after it")
	}
	// And it must not have cleared as a side effect either: a clear bumps the
	// changeCount, so an unchanged count is the proof nothing happened.
	if got := changeCount(board); got != theirs {
		t.Errorf("changeCount moved from %d to %d on a refused clear, so something was modified anyway", theirs, got)
	}
	if !hasType(board, concealedType) {
		t.Error("the user's copy lost its declared types on a refused clear")
	}
}

// ChangeCount exists for the caller that filled the board some other way
// (pbcopy, on the non-UTF-8 fallback) and still wants the clear contract. Its
// answer has to be usable as that handle.
func TestChangeCountIsUsableAsAClearHandle(t *testing.T) {
	board := testBoard(t)
	if _, err := writeConcealed(board, []byte("value")); err != nil {
		t.Fatalf("writeConcealed: %v", err)
	}
	if !clearIfUnchanged(board, changeCount(board)) {
		t.Error("a handle read straight from ChangeCount did not authorize a clear")
	}
}

// TestExportedChangeCountReadsTheGeneralPasteboard is the one delegation check
// that can be made without consequences: reading a changeCount does not modify
// anything, so the exported wrapper can be pointed at the real clipboard and
// compared against the seam it is supposed to be calling.
//
// WriteConcealed and ClearIfUnchanged get no equivalent, deliberately. Both
// mutate, so confirming they pass the general pasteboard means writing to — or
// clearing — the clipboard of whoever is running the suite, which is the exact
// thing this file's board naming exists to prevent. They stay uncovered for the
// same structural reason internal/screenlock's Watch does: a one-line wrapper
// whose only untested content is the argument it hard-codes, where reaching that
// argument in a test would mean touching the machine for real. The logic behind
// both is covered above.
func TestExportedChangeCountReadsTheGeneralPasteboard(t *testing.T) {
	if got, want := ChangeCount(), changeCount(""); got != want {
		t.Errorf("ChangeCount() = %d but changeCount(\"\") = %d; the exported entry point is not reading the general pasteboard", got, want)
	}
}

// TestWriteConcealedRejectsNonUTF8LeavingTheBoardAlone pins the fallback
// signal `jit vault get --copy` switches on: NSString cannot hold arbitrary
// bytes, so a binary secret has to go via pbcopy instead. The refusal must be
// reported rather than silently truncated — and it must not have half-written
// anything on the way to failing.
func TestWriteConcealedRejectsNonUTF8LeavingTheBoardAlone(t *testing.T) {
	board := testBoard(t)
	before := changeCount(board)

	count, err := writeConcealed(board, []byte{0xff, 0xfe, 0x00, 0x80})
	if err != ErrNotUTF8 {
		t.Fatalf("writeConcealed(invalid utf-8) error = %v, want ErrNotUTF8", err)
	}
	if count != 0 {
		t.Errorf("a refused write returned handle %d, want 0 — a caller could schedule a clear against it", count)
	}
	if got := changeCount(board); got != before {
		t.Errorf("changeCount moved from %d to %d on a refused write; the board was touched", before, got)
	}
}

// An empty value is not an error — `jit vault get --copy` on an empty secret
// is a strange thing to do but not a failure, and it must not be reported as
// the non-UTF-8 case, which would send the caller down the pbcopy fallback for
// no reason. (An empty slice also means writeConcealed passes a nil pointer,
// which is the branch this covers.)
func TestWriteConcealedAcceptsAnEmptyValue(t *testing.T) {
	board := testBoard(t)
	count, err := writeConcealed(board, nil)
	if err != nil {
		t.Fatalf("writeConcealed(empty) = %v, want no error", err)
	}
	if count == 0 {
		t.Error("an accepted write returned a zero handle")
	}
	if !hasType(board, concealedType) {
		t.Error("an empty value was written without the concealed marker")
	}
}
