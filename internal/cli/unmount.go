// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
)

var unmountYes bool

var unmountCmd = &cobra.Command{
	Use:     "unmount <path>",
	GroupID: groupSecrets,
	Short:   "Reverse a live .env mount back into a plain file",
	Long: "jit unmount decrypts a mounted .env's secrets from the vault and writes\n" +
		"them back out as a plain file at the same path, replacing the live-mounted\n" +
		"pipe jit migrate created. The vault secrets and the profile manifest are\n" +
		"left in place, only the physical mount is reversed.\n\n" +
		"If jit's background service is running, this stops serving just this one mount first, so\n" +
		"nothing races the file being replaced, every other mount keeps being\n" +
		"served undisturbed.",
	Example:           "  jit unmount ~/proj/.env",
	Args:              requireArgs(1, 1, "a mounted path (see `jit status`)"),
	ValidArgsFunction: completeMountPaths,
	RunE: func(cmd *cobra.Command, args []string) error {
		mountPath, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("jit unmount: %w", err)
		}

		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit unmount: %w", err)
		}
		registryPath := mount.RegistryPath(root)

		entry, found, err := mount.FindMount(registryPath, mountPath)
		if err != nil {
			return fmt.Errorf("jit unmount: %w", err)
		}
		if !found {
			// List the registered mounts right here — the old pointer sent
			// people to `jit status`, which only reports a COUNT, so a typo'd
			// or guessed path dead-ended with no way to learn the right one
			// (a real, reported miss: `jit unmount ./.`). The registry is a
			// plain local file; reading it costs nothing and needs no auth.
			entries, listErr := mount.LoadRegistry(registryPath)
			if listErr != nil || len(entries) == 0 {
				// The non-empty case below lists what IS mounted, so only this
				// branch left the reader with nowhere to look.
				return fmt.Errorf("jit unmount: no mount registered at %s, nothing is currently mounted (see `jit status`)", mountPath)
			}
			home, _ := os.UserHomeDir()
			lines := make([]string, 0, len(entries))
			for _, e := range entries {
				lines = append(lines, "  "+glyphBullet+" "+displayPath(home, e.MountPath))
			}
			return fmt.Errorf("jit unmount: no mount registered at %s, currently mounted:\n%s", mountPath, strings.Join(lines, "\n"))
		}

		// An orphaned mount: its profile manifest is gone — the whole project
		// directory was deleted without unmounting first (GAPS.md #67). There
		// are no secrets to decrypt and nowhere meaningful to write them back,
		// so the only sensible action is to clear the stale registry entry:
		// otherwise it blocks `jit vault delete` ("N file(s) still
		// live-mounted") forever, and the normal unmount path just errors with
		// "profile ... no such file or directory" with no way to recover short
		// of hand-editing mounts.yaml. This writes no plaintext and decrypts
		// nothing, so it needs no vault auth — only the registry edit and a
		// best-effort stop of any still-running serve goroutine.
		if _, statErr := os.Stat(entry.ProfilePath); os.IsNotExist(statErr) {
			if !unmountYes && !confirmPrompt(cmd, fmt.Sprintf(
				"The mount at %s is orphaned, its profile %s is gone (the project was likely deleted), so there are no secrets to write back. Remove the stale registry entry? [y/N] ",
				mountPath, entry.ProfilePath)) {
				fmt.Fprintln(cmd.OutOrStdout(), "Aborted. Nothing was changed.")
				return nil
			}
			if agentClient := agent.NewClient(agent.SocketPath(root)); agentClient.Reachable() {
				_ = agentClient.StopMount(mountPath) // best-effort: it may not even be serving this dead mount
			}
			if _, err := mount.RemoveMount(registryPath, mountPath); err != nil {
				return fmt.Errorf("jit unmount: %w", err)
			}
			_ = os.Remove(migrate.PointerFilePath(mountPath)) // best-effort; usually already gone with the project
			fmt.Fprintf(cmd.OutOrStdout(), "Removed the stale mount registration for %s (its project was already gone; nothing to restore).\n", mountPath)
			return nil
		}

		// Declining must never trigger a Touch ID prompt for work that's
		// about to be aborted — same ordering migrate/vault rm/vault
		// import already use. This is the one place in this command that
		// puts a real secret value back on disk in plaintext, so unlike
		// most of unmount's other side effects (stopping just this one
		// mount is reversible by re-registering it — e.g. re-running
		// `jit migrate`), it needs the same explicit confirmation
		// vault rm/import already require for their own less-reversible
		// actions.
		if !unmountYes && !confirmPrompt(cmd, fmt.Sprintf(
			"This decrypts %s's secrets and writes them back to disk in PLAINTEXT, replacing the live mount. Continue? [y/N] ", mountPath)) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted. Nothing was changed.")
			return nil
		}

		if agentClient := agent.NewClient(agent.SocketPath(root)); agentClient.Reachable() {
			if err := agentClient.StopMount(mountPath); err != nil {
				return fmt.Errorf("jit unmount: stopping the running service's mount: %w", err)
			}
		}

		// Fresh challenge on purpose, even while the agent session is
		// unlocked — see openVaultFreshAuth: putting real secrets back on
		// disk in plaintext should never happen silently on a cached
		// session some other same-user process could be riding.
		v, err := openVaultFreshAuth()
		if err != nil {
			return fmt.Errorf("jit unmount: %w", err)
		}
		// Force the fresh Touch ID/passcode NOW and record it into this
		// invocation's audit entry, the same gate jit migrate undo/remove use
		// — unmounting writes real secret values back to disk in plaintext.
		if err := requireFreshUserPresence(v, fmt.Sprintf("unmount %s (write its secret values back to disk in plaintext)", filepath.Base(mountPath))); err != nil {
			return fmt.Errorf("jit unmount: %w", err)
		}

		names, err := migrate.UnmountFile(v, entry.ProfilePath, mountPath, entry.TemplatePath)
		if err != nil {
			return fmt.Errorf("jit unmount: %w", err)
		}

		if _, err := mount.RemoveMount(registryPath, mountPath); err != nil {
			return fmt.Errorf("jit unmount: %w", err)
		}

		// The .pointers companion describes a mount that no longer exists —
		// stale the moment the plain file is back.
		// (A real leftover: unmount used to skip these, and a later `jit
		// migrate undo` only cleans them for still-REGISTERED mounts, so an
		// unmount-then-undo sequence orphaned the companion for good.) Both
		// removals are cosmetic relative to the unmount that already
		// succeeded, so a failure warns, never fails the command.
		if err := os.Remove(migrate.PointerFilePath(mountPath)); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: removing stale pointer file for %s: %v\n", mountPath, err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Unmounted %s (%s written back as plaintext).\n", mountPath, countWord(len(names), "variable", "variables"))
		fmt.Fprintln(cmd.OutOrStdout(), "The vault secrets and profile manifest are still there, only the mount itself was reversed.")
		return nil
	},
}

func init() {
	unmountCmd.Flags().BoolVarP(&unmountYes, "yes", "y", false, "skip the confirmation prompt and unmount immediately")
	rootCmd.AddCommand(unmountCmd)
}
