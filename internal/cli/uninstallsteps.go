// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"os"
	"strings"

	"github.com/jitpass/jit/internal/guard"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// The parts of `jit uninstall` that reach outside jit's own two directories.
// Each was something uninstall used to leave behind: a line in the shell
// config pointing at a directory it had just deleted, helper scripts no
// index records, a keychain key protecting nothing. They live here, away
// from runUninstall's prompts and messages, so each can be tested against a
// temp home.

// binaryOwner says who a jit binary at this resolved path belongs to, when
// that is not jit itself. Uninstall must not delete such a copy: one inside
// JitPass.app is part of the bundle's code signature, and one in a Homebrew
// tree is what brew's manifest describes. Homebrew first, as upgrade checks
// it: a brew-installed app is both, and brew is the one to ask.
func binaryOwner(resolvedPath string) string {
	switch {
	case brewManaged(resolvedPath):
		return "homebrew"
	case inAppBundle(resolvedPath):
		return "app"
	default:
		return ""
	}
}

// removeShimPathLine takes wrap's PATH line out of the login shell's config,
// but only once the shim directory holds nothing: the docker and git
// credential helpers live there too and are found strictly by $PATH lookup,
// the rule `jit wrap undo` already follows. Reports the file it edited, or
// "" when it left the line (or found none).
func removeShimPathLine(home, shell string) (string, error) {
	residents, err := wrap.ShimDirResidents(home)
	if err != nil {
		return "", err
	}
	if len(residents) > 0 {
		return "", nil
	}
	rc := wrap.RcFile(home, shell)
	changed, err := wrap.RemovePathLine(rc)
	if err != nil || !changed {
		return "", err
	}
	return rc, nil
}

// removeHelperScripts deletes the credential-helper scripts migrate drops.
// Two of them sit outside ~/.jit, so no directory removal ever reached them,
// and no backup record names any of the four. Only a purge calls this: a
// plain uninstall keeps the vault so that a reinstall picks up where it left
// off, and the tool configs still point at these.
func removeHelperScripts(home string) (removed []string, err error) {
	var errs []error
	for _, p := range helperScriptPaths(home) {
		switch rmErr := os.Remove(p); {
		case rmErr == nil:
			removed = append(removed, p)
		case !errors.Is(rmErr, os.ErrNotExist):
			errs = append(errs, rmErr)
		}
	}
	return removed, errors.Join(errs...)
}

// removeHistoryGuard is guard.Remove under the name uninstall reads it by.
// rcEdited is false when the user's own hand-written source line was kept.
func removeHistoryGuard(home string) (changed, rcEdited bool, err error) {
	return guard.Remove(home)
}

// deleteVaultKeys removes the master key and any key a half-finished rekey
// staged beside it. A var so no test can reach the production keychain: the
// same seam, for the same reason, as vaultMasterKeyPresence.
var deleteVaultKeys = func(ks keystore.Store) error {
	var errs []error
	if ks.Presence() != keystore.Absent {
		errs = append(errs, ks.Delete())
	}
	// The staged key a half-finished rekey left is the keychain's own item
	// until plan step B4.
	if w := keystore.Keychain(); w.StagedRekeyWrapper().MEKPresence() == keychainwrap.MEKPresent {
		errs = append(errs, w.DeleteStagedRekeyMEK())
	}
	return errors.Join(errs...)
}

// uninstallOpenVault is the strict gate: a vault opened on its own fresh
// fingerprint, never a cached service session. A var for the same reason.
var uninstallOpenVault = func(reason string) (*vault.Vault, error) {
	v, err := openVaultFreshAuth()
	if err != nil {
		return nil, err
	}
	return v, requireFreshUserPresence(v, reason)
}

// uninstallChallenge is the bare presence prompt, a var for the same reason.
var uninstallChallenge = keychainwrap.Challenge

// uninstallNeedsVaultKey reports whether the presence check should go
// through the vault's own key. It should whenever there are secrets to
// protect AND a key to fetch. With the key provably gone the vault is
// already unreadable, and insisting on it made uninstall impossible for
// exactly the person who most needs to start over; a human is still proven
// present by the bare challenge. An indeterminate probe keeps the strict
// path: only a definite absence relaxes it.
func uninstallNeedsVaultKey(secretCount int) bool {
	return secretCount > 0 && vaultMasterKeyPresence() != keystore.Absent
}

// helperScriptPaths is every credential-helper script migrate can drop.
func helperScriptPaths(home string) []string {
	return []string{
		migrate.TerraformHelperPath(home),
		migrate.CargoHelperPath(home),
		migrate.DockerHelperPath(home),
		migrate.GitHelperPath(home),
	}
}

// existingHelperScripts is the subset on disk now, for the plan.
func existingHelperScripts(home string) []string {
	var found []string
	for _, p := range helperScriptPaths(home) {
		if _, err := os.Lstat(p); err == nil {
			found = append(found, p)
		}
	}
	return found
}

// shimPathLineFile is the login shell's config when it carries wrap's PATH
// line, "" when it does not: the plan names the line only if it is there.
func shimPathLineFile(home, shell string) string {
	rc := wrap.RcFile(home, shell)
	data, err := os.ReadFile(rc) // #nosec G304 G703 -- one of three fixed rc names under the user's own home, picked by $SHELL's basename
	if err != nil || !wrap.RcMentionsShimDir(string(data)) {
		return ""
	}
	return rc
}

// displayPaths renders paths home-relative, comma separated.
func displayPaths(home string, paths []string) string {
	shown := make([]string, 0, len(paths))
	for _, p := range paths {
		shown = append(shown, displayPath(home, p))
	}
	return strings.Join(shown, ", ")
}
