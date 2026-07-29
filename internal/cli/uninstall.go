// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/wrap"
)

// This file is `jit uninstall`: the reverse of everything jit installs on a
// machine — the launchd login item, the wrap shims, and (with a resolved
// path prompt) the binary itself. It is deliberately conservative about the
// ONE thing it can't undo: your vault. jit is a secrets manager, the vault
// is the only copy on this Mac (status warns when there's no export on
// record), so a plain `jit uninstall` NEVER deletes it — it stops the
// software and tells you exactly where your secrets remain. Only the
// explicit `--purge` erases the vault and global config, and only after
// naming how many secrets that destroys.

var (
	uninstallPurge      bool
	uninstallYes        bool
	uninstallKeepBinary bool
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove jit's service, shims, and binary (keeps your vault unless --purge)",
	Long: "Removes jit from this Mac: stops and unloads the background service, deletes\n" +
		"the wrap shims, and removes the jit binary (prompts for sudo only if its path\n" +
		"isn't writable). \n\n" +
		"Your vault is NOT touched by default — jit is the only thing that can decrypt\n" +
		"it on this Mac, so uninstall leaves your secrets in place and tells you where\n" +
		"they are. Add --purge to also erase the vault and global config; uninstall\n" +
		"will name how many secrets that destroys and recommend `jit vault export`\n" +
		"first.\n\n" +
		"Uninstalling requires a fresh Touch ID/passcode approval — so someone at your\n" +
		"unlocked Mac can't remove jit (or --purge your secrets) without your presence.\n" +
		"--yes skips only the typed y/N confirmation, never the fingerprint. (This\n" +
		"guards the `jit uninstall` path; it is not a substitute for file permissions —\n" +
		"anyone with your shell can still delete files directly.)",
	Args:    cobra.NoArgs,
	GroupID: groupService,
	RunE:    runUninstall,
}

func runUninstall(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit uninstall: %w", err)
	}
	vaultRoot, err := vaultRootDir()
	if err != nil {
		return fmt.Errorf("jit uninstall: %w", err)
	}
	plistPath, _ := agentPlistPath()

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jit uninstall: locating the running binary: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exePath); rerr == nil {
		exePath = resolved
	}

	shims, _ := wrap.InstalledShims(home)
	jitConfigDir := filepath.Join(home, ".jit")
	secretCount := vaultSecretCount()

	// Lay out the plan before doing anything, so the confirmation is informed.
	fmt.Fprintln(out, "This will remove:")
	fmt.Fprintln(out, "  - the background service (launchd login item)")
	if len(shims) > 0 {
		fmt.Fprintf(out, "  - %s: %v\n", countWord(len(shims), "wrap shim", "wrap shims"), shims)
	}
	if !uninstallKeepBinary {
		fmt.Fprintf(out, "  - the jit binary at %s\n", exePath)
	}
	if uninstallPurge {
		fmt.Fprintf(out, "  - the global config at %s\n", jitConfigDir)
		fmt.Fprintf(out, "  - THE VAULT at %s", vaultRoot)
		if secretCount >= 0 {
			fmt.Fprintf(out, " (%s — this is irreversible)", countWord(secretCount, "secret", "secrets"))
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out)
	if uninstallPurge {
		fmt.Fprintln(out, "PURGE also deletes your secrets. If you might want them back, run")
		fmt.Fprintln(out, hlCmds("`jit vault export <file>` first — there is no other copy on this Mac."))
	} else {
		fmt.Fprintf(out, "Your vault at %s is kept.\n", vaultRoot)
	}

	if !uninstallYes {
		prompt := "Uninstall jit? [y/N] "
		if uninstallPurge {
			prompt = fmt.Sprintf("Permanently delete jit AND %s? [y/N] ", countWord(secretCount, "secret", "secrets"))
		}
		if !confirmPrompt(cmd, prompt) {
			fmt.Fprintln(out, "Aborted, nothing was changed.")
			return nil
		}
	}

	// Security gate: a fresh fingerprint, required even under --yes. Removing
	// jit (and especially --purge erasing the vault) is exactly the kind of
	// destructive act an attacker at an unlocked Mac would reach for, so it
	// gets the same fresh-user-presence challenge as `jit migrate remove`,
	// answered by THIS process (never a cached agent session). Placed after
	// the confirm so a decline never costs a Touch ID prompt.
	if err := requireUninstallPresence(secretCount); err != nil {
		return fmt.Errorf("jit uninstall: authorization failed, nothing was changed: %w", err)
	}

	var failures []string
	note := func(format string, a ...any) { fmt.Fprintf(out, format+"\n", a...) }

	// 1. Service: boot it out of launchd and remove the login item. bootout is
	//    best-effort (nothing loaded is a success, not a failure); removing the
	//    plist is what actually stops it from coming back at next login.
	_, _ = launchctlRun("bootout", agentServiceTarget())
	if plistPath != "" {
		if err := os.Remove(plistPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Sprintf("removing %s: %v", plistPath, err))
		} else {
			note("Removed the background service.")
		}
	}

	// 2. Shims: un-wrap every tool. RemoveShim refuses to delete a non-symlink,
	//    so a user's own file that happens to share a name is never touched.
	removedShims := 0
	for _, tool := range shims {
		if ok, err := wrap.RemoveShim(home, tool); err != nil {
			failures = append(failures, fmt.Sprintf("removing shim %q: %v", tool, err))
		} else if ok {
			removedShims++
		}
	}
	if removedShims > 0 {
		note("Removed %s.", countWord(removedShims, "wrap shim", "wrap shims"))
	}

	// 3. Purge (opt-in): global config, then the vault. Order matters only for
	//    messaging — both are just directory removals.
	if uninstallPurge {
		if err := os.RemoveAll(jitConfigDir); err != nil {
			failures = append(failures, fmt.Sprintf("removing %s: %v", jitConfigDir, err))
		} else {
			note("Removed global config at %s.", jitConfigDir)
		}
		if err := os.RemoveAll(vaultRoot); err != nil {
			failures = append(failures, fmt.Sprintf("removing %s: %v", vaultRoot, err))
		} else {
			note("Erased the vault at %s.", vaultRoot)
		}
	}

	// 4. Binary last: once it's gone the running process stays in memory long
	//    enough to finish these messages, but nothing should run after it.
	if !uninstallKeepBinary {
		if err := removePath(exePath); err != nil {
			failures = append(failures, fmt.Sprintf("removing %s: %v", exePath, err))
		} else {
			note("Removed the jit binary at %s.", exePath)
		}
	}

	fmt.Fprintln(out)
	if len(failures) > 0 {
		fmt.Fprintln(out, "Uninstall finished with problems:")
		for _, f := range failures {
			fmt.Fprintf(out, "  - %s\n", f)
		}
		return errors.New("jit uninstall: some steps did not complete (see above)")
	}

	if uninstallPurge {
		fmt.Fprintln(out, "jit is fully removed. Goodbye.")
	} else {
		fmt.Fprintln(out, "jit is uninstalled. Your vault remains at:")
		fmt.Fprintf(out, "  %s\n", vaultRoot)
		fmt.Fprintf(out, "  %s\n", filepath.Join(home, ".jit"))
		fmt.Fprintln(out, "Reinstall jit any time to use it again, or `rm -rf` those paths to erase your secrets.")
	}
	return nil
}

// requireUninstallPresence forces a fresh Touch ID/passcode gesture before
// anything is removed. When the vault holds secrets it challenges through the
// vault's own key wrapper (requireFreshUserPresence — the biometric-gated MEK
// fetch, which also stamps the fresh auth into the audit record); with no
// secrets to protect there's no MEK to gate on, so it falls back to a bare
// LocalAuthentication prompt that still proves a human is present. Either way
// the gesture is unskippable — that's the whole point of gating uninstall.
func requireUninstallPresence(secretCount int) error {
	reason := "authorize uninstalling jit from this Mac"
	if uninstallPurge {
		reason = "authorize erasing jit and its vault from this Mac"
	}
	if secretCount > 0 {
		v, err := openVaultFreshAuth()
		if err != nil {
			return err
		}
		return requireFreshUserPresence(v, reason)
	}
	return keychainwrap.Challenge(reason)
}

// removePath deletes a single file, escalating to `sudo rm -f` only when a
// direct unlink is refused because the containing directory isn't writable
// (a root-owned /usr/local/bin). Mirrors upgrade's replaceBinary sudo path.
func removePath(path string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if !dirWritable(filepath.Dir(path)) {
		// #nosec G204 -- path is os.Executable(), never external input
		c := sudoCommand("/bin/rm", "-f", path)
		if runErr := c.Run(); runErr != nil {
			return fmt.Errorf("sudo rm: %w", runErr)
		}
		return nil
	}
	return err
}

// vaultSecretCount returns how many secrets the vault holds, or -1 if that
// can't be read (no vault yet, or an unreadable one) — the count is only for
// an honest confirmation message, never a gate, so an unknown count must not
// block uninstall.
func vaultSecretCount() int {
	v, err := openVaultReadOnly()
	if err != nil {
		return -1
	}
	paths, err := v.List()
	if err != nil {
		return -1
	}
	return len(paths)
}

func init() {
	uninstallCmd.Flags().BoolVar(&uninstallPurge, "purge", false, "also erase the vault and global config (destroys your secrets)")
	uninstallCmd.Flags().BoolVarP(&uninstallYes, "yes", "y", false, "skip the typed y/N confirmation (still requires the Touch ID/passcode gate)")
	uninstallCmd.Flags().BoolVar(&uninstallKeepBinary, "keep-binary", false, "leave the jit binary in place (e.g. it's managed by a package manager)")
	rootCmd.AddCommand(uninstallCmd)
}
