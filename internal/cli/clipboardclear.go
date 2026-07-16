// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/pasteboard"
)

// clipboardClearDelay is how long a secret copied by `jit vault get
// --copy` stays on the pasteboard before the detached helper clears it.
// Long enough to paste into a login form (or fumble it once), short
// enough that walking away doesn't leave a live credential behind —
// the same ballpark password managers converged on.
const clipboardClearDelay = 45 * time.Second

var (
	clipboardClearAfter time.Duration
	clipboardClearCount int64
)

// clipboardClearCmd is internal plumbing, spawned detached by `jit vault
// get --copy`: sleep, then clear the pasteboard ONLY if its changeCount
// still matches the copy that scheduled us — anything the user copied in
// the meantime is theirs, not ours to clear. Fully hidden (no
// helpVisibleAnnotation, like docs-gen): running it by hand is
// meaningless, and its flags are an internal contract, not an interface.
var clipboardClearCmd = &cobra.Command{
	Use:     "_clipboard-clear",
	GroupID: groupPlumbing, // spawned by jit itself; hidden, so never rendered under the group anyway
	Hidden:  true,
	Short:  "Clear the pasteboard after a delay if it still holds jit's copy (internal)",
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		time.Sleep(clipboardClearAfter)
		pasteboard.ClearIfUnchanged(clipboardClearCount)
		return nil
	},
}

// spawnClipboardClear starts the detached helper that will clear the
// pasteboard write identified by changeCount. Setsid + released handle:
// the helper must outlive this CLI invocation by design, and must never
// hold the terminal.
func spawnClipboardClear(changeCount int64) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	c := exec.Command(exe, "_clipboard-clear", // #nosec G204 -- exe is this same jit binary, from os.Executable
		"--change-count", strconv.FormatInt(changeCount, 10),
		"--after", clipboardClearDelay.String())
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		return err
	}
	return c.Process.Release()
}

func init() {
	clipboardClearCmd.Flags().Int64Var(&clipboardClearCount, "change-count", -1, "pasteboard changeCount identifying the write to clear")
	clipboardClearCmd.Flags().DurationVar(&clipboardClearAfter, "after", clipboardClearDelay, "how long to wait before clearing")
	rootCmd.AddCommand(clipboardClearCmd)
}
