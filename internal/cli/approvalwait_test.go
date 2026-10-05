// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// A command killed while its approval prompt is up never returns to
// Execute, so awaitApproval writes its audit line before letting the
// signal end the process (release QA: killed undo runs were missing from
// `jit audit`).
func TestAwaitApprovalRecordsACommandKilledAtThePrompt(t *testing.T) {
	origRecord, origDie, origCmd, origRecorded := recordInvocation, dieBySignal, invocationCmd, invocationRecorded
	t.Cleanup(func() {
		recordInvocation, dieBySignal, invocationCmd, invocationRecorded = origRecord, origDie, origCmd, origRecorded
	})
	type rec struct {
		cmd string
		err error
	}
	recorded := make(chan rec, 2)
	recordInvocation = func(cmd *cobra.Command, err error, _ time.Duration) {
		recorded <- rec{cmd.CommandPath(), err}
	}
	died := make(chan os.Signal, 1)
	dieBySignal = func(sig os.Signal) { died <- sig }
	invocationRecorded = false
	invocationCmd = &cobra.Command{Use: "undo"}

	errDenied := errors.New("prompt closed")
	err := awaitApproval(func() error {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case <-died: // the process would be gone here; the prompt closes with it
		case <-time.After(5 * time.Second):
			t.Fatal("the signal did not end the wait")
		}
		return errDenied
	})
	if !errors.Is(err, errDenied) {
		t.Fatalf("awaitApproval returned %v", err)
	}
	select {
	case r := <-recorded:
		if r.cmd != "undo" || r.err == nil || !strings.Contains(r.err.Error(), "stopped by SIGTERM while waiting for approval") {
			t.Fatalf("recorded %q with %v", r.cmd, r.err)
		}
	default:
		t.Fatal("no audit line for the killed command")
	}
	if !invocationRecorded {
		t.Error("Execute would record the command a second time")
	}
}

// Outside a kill, the wait is transparent: its result passes through and
// nothing is recorded early.
func TestAwaitApprovalPassesTheResultThrough(t *testing.T) {
	origRecord := recordInvocation
	t.Cleanup(func() { recordInvocation = origRecord })
	recordInvocation = func(*cobra.Command, error, time.Duration) { t.Error("recorded before the command finished") }
	if err := awaitApproval(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	want := errors.New("denied")
	if err := awaitApproval(func() error { return want }); err != want {
		t.Fatalf("got %v, want the wait's own error", err)
	}
}
