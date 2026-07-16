// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/vault"
)

var vaultRekeyYes bool

// rekeyMarkerPath is the in-progress marker `jit vault rekey` holds for
// the duration of a rotation. While it exists, openVault/openVaultFreshAuth
// refuse to operate: mid-rekey some envelopes open under the old key and
// some under the staged one, and a write in that window (an agent-cached
// wrap, a plain `jit vault set`) could seal new data under a key about to
// be deleted. Bookkeeping, not secret material — root-level, like
// device.id.
func rekeyMarkerPath(root string) string {
	return filepath.Join(root, "rekey.inprogress")
}

func rekeyInProgress(root string) bool {
	_, err := os.Stat(rekeyMarkerPath(root))
	return err == nil
}

// errRekeyInProgress is what every other vault command reports while the
// marker exists — including after an interrupted rotation, which is
// exactly when a user will be running other commands wondering why.
var errRekeyInProgress = fmt.Errorf("a master-key rotation is in progress (or was interrupted) — run `jit vault rekey` to finish it first")

var vaultRekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Rotate the vault's master encryption key",
	Long: "Generates a new master encryption key, re-wraps every stored secret's key\n" +
		"under it (live secrets, file backups, and archived versions — the encrypted\n" +
		"values themselves are never touched), then replaces the old master key.\n" +
		"One Touch ID/passcode approval covers the whole operation.\n\n" +
		"Run it if the old key may have been exposed, or simply on a schedule —\n" +
		"the vault's master key otherwise never changes for its whole life.\n\n" +
		"Safe to interrupt: until the very last step both keys exist, every\n" +
		"re-wrapped secret is verified before it's written, and re-running\n" +
		"`jit vault rekey` finishes an interrupted rotation. Other vault commands\n" +
		"refuse to write while one is in progress.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit vault rekey: %w", err)
		}

		resume := rekeyInProgress(root)
		primary := keychainwrap.New()
		hasPrimary := primary.HasMEK()
		if !hasPrimary && !resume {
			return fmt.Errorf("jit vault rekey: no vault master key found — run `jit vault init` first")
		}

		if !vaultRekeyYes {
			prompt := "Rotate the vault's master key? Every stored secret is re-wrapped under a new one. [y/N] "
			if resume {
				prompt = "An interrupted rekey is in progress. Finish it now? [y/N] "
			}
			if !confirmPrompt(cmd, prompt) {
				fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
				return nil
			}
		}

		// One challenge for the whole operation. The normal path rides the
		// primary fetch (also caching the old MEK this run needs anyway);
		// the resume-after-promote-crash path has no primary left to fetch,
		// so the gesture is a bare challenge instead — skipping it there
		// would make "kill rekey at the right moment" a way to finish a
		// rotation with no approval at all.
		if hasPrimary {
			if err := primary.RequireUserPresence("rotate the vault's master encryption key"); err != nil {
				return fmt.Errorf("jit vault rekey: %w", err)
			}
		} else {
			if err := keychainwrap.Challenge("finish rotating the vault's master encryption key"); err != nil {
				return fmt.Errorf("jit vault rekey: %w", err)
			}
		}

		// Drop the agent's cached session on both sides of the rotation:
		// before, so nothing keeps wrapping under the old MEK mid-rekey
		// (the marker blocks new vault opens, but an already-unlocked
		// agent holds its copy in memory); after, so the next use fetches
		// the NEW key instead of serving a dead one from cache. Both
		// best-effort — no agent running is fine.
		lockAgent()
		defer lockAgent()

		if err := vault.AtomicWriteFile(rekeyMarkerPath(root), fmt.Appendf(nil, "started %s\n", time.Now().Format(time.RFC3339))); err != nil {
			return fmt.Errorf("jit vault rekey: %w", err)
		}
		if err := primary.EnsureStagedRekeyMEK(); err != nil {
			return fmt.Errorf("jit vault rekey: staging new key: %w", err)
		}

		v, err := openVaultReadOnly() // KeyWrapper unused: RewrapAll takes both explicitly
		if err != nil {
			return fmt.Errorf("jit vault rekey: %w", err)
		}
		var oldKW vault.KeyWrapper
		if hasPrimary {
			oldKW = primary
		} else {
			fmt.Fprintln(cmd.ErrOrStderr(), "jit vault rekey: resuming — the old master key is already gone; verifying every secret opens under the staged key.")
		}
		rewrapped, current, err := v.RewrapAll(oldKW, primary.StagedRekeyWrapper())
		if err != nil {
			// Marker stays: the vault is mid-rotation and other commands
			// must keep refusing to write until a re-run gets past this.
			return fmt.Errorf("jit vault rekey: %w (both keys are intact — fix the cause and re-run `jit vault rekey`)", err)
		}

		if err := primary.PromoteStagedRekeyMEK(); err != nil {
			return fmt.Errorf("jit vault rekey: %w (re-run `jit vault rekey` to retry the final step)", err)
		}
		if err := os.Remove(rekeyMarkerPath(root)); err != nil {
			return fmt.Errorf("jit vault rekey: removing marker: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Master key rotated. %d envelope(s) re-wrapped", rewrapped)
		if current > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), " (%d already current from an interrupted run)", current)
		}
		fmt.Fprintln(cmd.OutOrStdout(), ". The old master key has been destroyed.")
		return nil
	},
}

// lockAgent drops a running agent's session, best-effort — rekey's
// bracket around the rotation. Deliberately quiet on failure: no agent
// (or an unreachable one) is the common, fine case.
func lockAgent() {
	if c, err := agentClient(); err == nil && c.Reachable() {
		_ = c.Lock()
	}
}

func init() {
	vaultRekeyCmd.Flags().BoolVar(&vaultRekeyYes, "yes", false, "skip the confirmation prompt")
	vaultCmd.AddCommand(vaultRekeyCmd)
}
