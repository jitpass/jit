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

	"github.com/jitpass/jit/internal/guard"
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
		"A copy of jit inside JitPass.app, or one Homebrew installed, is left where\n" +
		"it is: the app and brew own those, and uninstall says which to ask.\n\n" +
		"Your vault is NOT touched by default — jit is the only thing that can decrypt\n" +
		"it on this Mac, so uninstall leaves your secrets in place and tells you where\n" +
		"they are. Add --purge to also erase the vault and global config; uninstall\n" +
		"will name how many secrets that destroys and recommend `jit vault export`\n" +
		"first. A purge leaves nothing of jit's behind: the vault's key in the macOS\n" +
		"keychain, the history guard and its line in ~/.zshrc, the shim PATH line,\n" +
		"and the credential-helper scripts `jit migrate` installed all go with it.\n" +
		"It does NOT put migrated files back; run `jit migrate undo <path>` first.\n\n" +
		"Uninstalling requires a fresh Touch ID/passcode approval — so someone at your\n" +
		"unlocked Mac can't remove jit (or --purge your secrets) without your presence.\n" +
		"--yes skips only the typed y/N confirmation, never the fingerprint. (This\n" +
		"guards the `jit uninstall` path; it is not a substitute for file permissions —\n" +
		"anyone with your shell can still delete files directly.) When the vault's\n" +
		"key is already missing from the keychain, the same prompt runs without it,\n" +
		"so a vault nothing can open never blocks its own removal.",
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
	// A copy inside JitPass.app or a Homebrew tree is not jit's to delete:
	// the first is part of the bundle's signature, the second is what brew's
	// manifest describes. `jit upgrade` refuses both for the same reason.
	owner := binaryOwner(exePath)
	keepBinary := uninstallKeepBinary || owner != ""
	guardOn := uninstallPurge && guard.Installed(home)
	helpers := existingHelperScripts(home)
	keyGone := secretCount > 0 && !uninstallNeedsVaultKey(secretCount)

	// Lay out the plan before doing anything, so the confirmation is informed.
	fmt.Fprintln(out, "This will remove:")
	fmt.Fprintln(out, "  - the background service (launchd login item)")
	if len(shims) > 0 {
		fmt.Fprintf(out, "  - %s: %v\n", countWord(len(shims), "wrap shim", "wrap shims"), shims)
	}
	if uninstallPurge {
		if rc := shimPathLineFile(home, os.Getenv("SHELL")); rc != "" {
			fmt.Fprintf(out, "  - the shim PATH line in %s\n", displayPath(home, rc))
		}
		if guardOn {
			fmt.Fprintf(out, "  - the history guard and its line in %s\n", displayPath(home, guard.RcPath(home)))
		}
		if len(helpers) > 0 {
			fmt.Fprintf(out, "  - %s: %s\n", countWord(len(helpers), "credential helper", "credential helpers"), displayPaths(home, helpers))
		}
	}
	if !keepBinary {
		fmt.Fprintf(out, "  - the jit binary at %s\n", exePath)
	}
	if uninstallPurge {
		fmt.Fprintf(out, "  - the global config at %s\n", jitConfigDir)
		fmt.Fprintf(out, "  - THE VAULT at %s", vaultRoot)
		if secretCount >= 0 {
			fmt.Fprintf(out, " (%s — this is irreversible)", countWord(secretCount, "secret", "secrets"))
		}
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  - the vault's key in the macOS keychain")
	}
	switch owner {
	case "app":
		fmt.Fprintln(out, "This jit binary stays: it is part of JitPass.app. Move the app to the Trash to remove it.")
	case "homebrew":
		fmt.Fprintln(out, hlCmds("This jit binary stays: Homebrew installed it. `brew uninstall --cask jitpass` removes it."))
	}
	fmt.Fprintln(out)
	if keyGone {
		fmt.Fprintf(out, "The vault's key is missing from the keychain, so its %s cannot be read\nby anything. Touch ID still confirms it is you.\n", countWord(secretCount, "secret", "secrets"))
	}
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
		// Before ~/.jit goes: the guard's remover reads its own hook path, and
		// two of the helpers live outside any directory removed below.
		if guardOn {
			if _, rcEdited, err := removeHistoryGuard(home); err != nil {
				failures = append(failures, fmt.Sprintf("removing the history guard: %v", err))
			} else if rcEdited {
				note("Removed the history guard and its line in %s.", displayPath(home, guard.RcPath(home)))
			} else {
				note("Removed the history guard. Your own source line in %s was left alone.", displayPath(home, guard.RcPath(home)))
			}
		}
		if removed, err := removeHelperScripts(home); err != nil {
			failures = append(failures, fmt.Sprintf("removing credential helpers: %v", err))
		} else if len(removed) > 0 {
			note("Removed %s.", countWord(len(removed), "credential helper", "credential helpers"))
		}
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
		// Last of the purge, and only once the vault is gone: a key left
		// behind protects nothing, and makes the next install look set up.
		if err := deleteVaultKeys(); err != nil {
			failures = append(failures, fmt.Sprintf("removing the vault's keychain key: %v", err))
		} else {
			note("Removed the vault's key from the macOS keychain.")
		}
	}

	// The PATH line goes once nothing in the shim directory needs it: after
	// a purge that is always, after a plain uninstall only when no credential
	// helper still lives there (the rule `jit wrap undo` follows).
	if rc, err := removeShimPathLine(home, os.Getenv("SHELL")); err != nil {
		failures = append(failures, fmt.Sprintf("removing the shim PATH line: %v", err))
	} else if rc != "" {
		note("Removed the shim PATH line from %s.", displayPath(home, rc))
	}

	// 4. Binary last: once it's gone the running process stays in memory long
	//    enough to finish these messages, but nothing should run after it.
	if !keepBinary {
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
		fmt.Fprintln(out, hlCmds("Reinstall jit any time to use it again, or `rm -rf` those paths to erase your secrets."))
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
	if uninstallNeedsVaultKey(secretCount) {
		v, err := openVaultFreshAuth()
		if err != nil {
			return err
		}
		return requireFreshUserPresence(v, reason)
	}
	return uninstallChallenge(reason)
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
