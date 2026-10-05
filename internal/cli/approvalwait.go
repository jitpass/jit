// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// awaitApproval runs wait, a command blocked on its own approval prompt
// (Touch ID or password), so that a kill there still leaves an audit line.
// A command is recorded when it returns (Execute), and one stopped by
// Ctrl-C, a closed terminal or a timeout's SIGTERM never returns: release
// QA's killed `jit migrate undo` and `jit wrap undo az` were nowhere in
// `jit audit`, while the service logged its own unanswered prompts.
//
// Only around the wait, never for the whole command: commands that clean
// up on a signal of their own (a store run resealing, `jit aws-sso`, the
// service) must keep their handling, and nothing has changed yet while the
// prompt is up, so dying there is safe. The signal is re-raised once the
// line is written, and the process ends as it would have.
func awaitApproval(wait func() error) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	defer func() {
		signal.Stop(sigs)
		close(done)
	}()
	go func() {
		select {
		case sig := <-sigs:
			recordStoppedInvocation(sig)
			dieBySignal(sig)
		case <-done:
		}
	}()
	return wait()
}

// recordStoppedInvocation writes the line Execute never will.
func recordStoppedInvocation(sig os.Signal) {
	if recordInvocation == nil || invocationRecorded || invocationCmd == nil {
		return
	}
	invocationRecorded = true
	recordInvocation(invocationCmd, fmt.Errorf("stopped by %s while waiting for approval", signalName(sig)), time.Since(invocationStart))
}

func signalName(sig os.Signal) string {
	switch sig {
	case syscall.SIGINT:
		return "Ctrl-C (SIGINT)"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGHUP:
		return "a closed terminal (SIGHUP)"
	}
	return sig.String()
}

// dieBySignal ends the process the way the signal would have: default
// action restored, then sent again. A var so a test can stay alive.
var dieBySignal = func(sig os.Signal) {
	signal.Reset(sig)
	if s, ok := sig.(syscall.Signal); ok {
		_ = syscall.Kill(os.Getpid(), s)
	}
	// The default action is to terminate; should the re-raise not land,
	// exit with the shell's status for it.
	time.Sleep(time.Second)
	if s, ok := sig.(syscall.Signal); ok {
		os.Exit(128 + int(s))
	}
	os.Exit(1)
}

// invocationCmd is the command being run, set beside invocationCommandPath
// by the root PersistentPreRun, for a record written mid-command.
var invocationCmd *cobra.Command
