// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/vault"
)

var (
	vaultRekeyYes     bool
	vaultRekeyWrapper string
	vaultRekeyForce   bool
)

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
var errRekeyInProgress = fmt.Errorf("a master-key rotation is in progress (or was interrupted), run `jit vault rekey` to finish it first")

var vaultRekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Rotate the vault's master key, or move it into the Secure Enclave",
	Long: "Does one of two things to the vault's master key.\n\n" +
		"Without --wrapper, it rotates the key.\n" +
		"It generates a new master key,\n" +
		"re-wraps every stored secret's key under it\n" +
		"(live secrets, file backups and archived versions;\n" +
		"the encrypted values themselves are never touched),\n" +
		"then replaces the old master key.\n" +
		"One Touch ID/passcode approval covers the whole operation.\n" +
		"Run it if the old key may have been exposed, or on a schedule;\n" +
		"otherwise the master key never changes for the vault's whole life.\n\n" +
		"A rotation is safe to interrupt: until the last step both keys exist,\n" +
		"every re-wrapped secret is verified before it's written,\n" +
		"and running `jit vault rekey` again finishes it.\n" +
		"Other vault commands refuse to write while one is in progress.\n\n" +
		"With --wrapper, it moves the key and doesn't change it.\n" +
		"Nothing is re-encrypted, and your grants and AI jobs keep working;\n" +
		"their own keys follow the next time the jit service starts.\n" +
		"--wrapper secure-enclave moves the key from your login keychain\n" +
		"into this Mac's Secure Enclave.\n" +
		"There, only JitPass can use it, after Touch ID or your password,\n" +
		"and no other program running as you can read it.\n" +
		"--wrapper keychain moves it back.\n\n" +
		"Before a move into the Secure Enclave,\n" +
		"save a recovery file with `jit vault export <file>`;\n" +
		"jit refuses the move until one is newer than your newest secret.\n" +
		"After the move the key can't leave this Mac:\n" +
		"if the Mac is lost, replaced or erased,\n" +
		"that file is how your secrets come back.\n" +
		"A move works only from the jit inside JitPass.app;\n" +
		"any other copy of jit is refused.\n" +
		"In the app, Settings › Protection makes the same move.\n" +
		"An interrupted move finishes when you run the same command again.",
	Example: "  jit vault rekey                              # rotate the master key\n" +
		"  jit vault export ~/jit-recovery.json         # a recovery file, before a move\n" +
		"  jit vault rekey --wrapper secure-enclave     # move the key into the Secure Enclave\n" +
		"  jit vault rekey --wrapper keychain           # move it back to the keychain",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit vault rekey: %w", err)
		}

		if vaultRekeyWrapper != "" {
			return runVaultMove(cmd, root, vaultRekeyWrapper)
		}
		// A move and a rotation share the marker, never each other's work,
		// and a rotation resumes only over a marker it can prove is a
		// rotation's: resuming over a half-done move this jit can't read
		// would rewrap under a key the move may be about to delete.
		switch m := readRekeyMarker(root); m.kind {
		case markerMove:
			return fmt.Errorf("jit vault rekey: a move of the vault key is unfinished; run `jit vault rekey --wrapper %s` to finish it", m.target)
		case markerOtherMove, markerUnknown:
			return fmt.Errorf("jit vault rekey: %w", rekeyMarkerRefusal(root))
		}
		// Rotation rewrites the keychain item; an enclave vault does not use
		// one. Rotating an enclave vault's key is not built yet.
		if openKeyStore(root).Kind() == keystore.KindSecureEnclave {
			return errors.New("jit vault rekey: this vault's key is in the Secure Enclave, and rotating it is not available yet")
		}
		resume := rekeyInProgress(root)
		// Rekey rotates the keychain item's own bytes through staged items;
		// it stays keychain-specific until plan step B4.
		primary := keystore.Keychain()
		hasPrimary := primary.HasMEK()
		if !hasPrimary && !resume {
			return fmt.Errorf("jit vault rekey: no vault master key found, run `jit vault init` first")
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
			if err := primary.RequireUserPresence(reasonRekey); err != nil {
				return fmt.Errorf("jit vault rekey: %w", err)
			}
		} else {
			if err := keychainwrap.Challenge(reasonRekeyFinish); err != nil {
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
			fmt.Fprintln(cmd.ErrOrStderr(), "jit vault rekey: resuming, the old master key is already gone; verifying every secret opens under the staged key.")
		}
		// RewrapAll re-wraps every stored envelope one keychain/agent call at a
		// time and can run for a while on a large vault with nothing to show
		// for it. A single animated step tells the user it's working; it needs
		// no per-secret counter to stop looking hung, and threading one into
		// RewrapAll would churn its whole test surface. Stopped before the
		// result line prints.
		progress := newProgress(cmd, false)
		progress.Step("Re-wrapping every secret under the new master key…", "Re-wrapped every secret under the new master key")
		result, err := v.Rewrap(oldKW, primary.StagedRekeyWrapper())
		rewrapped, current := result.Rewrapped, result.Current
		progress.Stop()
		if err != nil {
			// Marker stays: the vault is mid-rotation and other commands
			// must keep refusing to write until a re-run gets past this.
			return fmt.Errorf("jit vault rekey: %w (both keys are intact, fix the cause and re-run `jit vault rekey`)", err)
		}

		if err := primary.PromoteStagedRekeyMEK(); err != nil {
			return fmt.Errorf("jit vault rekey: %w (re-run `jit vault rekey` to retry the final step)", err)
		}
		if err := os.Remove(rekeyMarkerPath(root)); err != nil {
			return fmt.Errorf("jit vault rekey: removing marker: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Master key rotated. %s re-wrapped", countWord(rewrapped, "envelope", "envelopes"))
		if current > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), " (%d already current from an interrupted run)", current)
		}
		fmt.Fprintln(cmd.OutOrStdout(), ". The old master key has been destroyed.")
		printKeptLostKeyCopies(cmd.OutOrStdout(), result.Kept)
		return nil
	},
}

// printKeptLostKeyCopies says how many envelopes a rotation left as they were
// because they are sealed to a lost Secure Enclave key (vault.Rewrap): no
// key on this Mac opens them, and they stay on disk for the recovery file,
// or a key found again, to bring back.
func printKeptLostKeyCopies(w io.Writer, kept []string) {
	if len(kept) == 0 {
		return
	}
	fmt.Fprintf(w, "Left %s sealed to a lost key as %s: no key on this Mac opens %s.\n",
		countWord(len(kept), "file", "files"), pluralWord(len(kept), "it was", "they were"), pluralWord(len(kept), "it", "them"))
}

// lockAgent drops a running agent's session, best-effort — rekey's
// bracket around the rotation. Deliberately quiet on failure: no agent
// (or an unreachable one) is the common, fine case.
func lockAgent() {
	// NoHeal: a dead service already holds no session — the bracket's goal —
	// so demand-starting one just to lock it would be a pointless spawn.
	if c, err := agentClientNoHeal(); err == nil && c.Reachable() {
		_ = c.Lock()
	}
}

func init() {
	vaultRekeyCmd.Flags().BoolVarP(&vaultRekeyYes, "yes", "y", false, "skip the confirmation prompt")
	// Shown since v2.3.0, the release whose JitPass carries the signed helper
	// bundle that can reach the enclave (design/secure-enclave-plan.md, A2).
	// A jit outside JitPass.app is refused with a sentence that says so.
	vaultRekeyCmd.Flags().StringVar(&vaultRekeyWrapper, "wrapper", "", `move the key instead of rotating it: "secure-enclave" or "keychain"`)
	// With --wrapper secure-enclave on a vault already in the enclave:
	// delete the keychain item under the vault key's name even when it is
	// not this vault's key, or can't be read (removeKeychainCopy). Stays
	// hidden: doctor never offers it, and it deletes a key on a typed yes.
	vaultRekeyCmd.Flags().BoolVar(&vaultRekeyForce, "force", false, "with --wrapper secure-enclave: also delete a keychain key that isn't this vault's")
	_ = vaultRekeyCmd.Flags().MarkHidden("force")
	vaultCmd.AddCommand(vaultRekeyCmd)
}
