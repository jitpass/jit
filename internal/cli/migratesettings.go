// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"os"
	"path"
	"sort"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/settings"
	"github.com/jitpass/jit/internal/vault"
)

var migrateSettingsFormat string

// jit migrate settings is the cleanup for profiles protected before only
// secrets went into the vault (design/secrets-only-vault.md, D5): it reads
// every vault entry that came from a .env, and moves out the ones the scan
// calls settings. Reading them is the only way to judge them, so it is one
// Touch ID for the whole run, and --dry-run asks for it too. A value the
// scan counts as a secret, or a name that says secret ("check"), stays.
var migrateSettingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Move the plain settings out of profiles protected before settings stayed plain",
	Long: "Read every vault entry that came from a protected .env, and move the ones the scan\n" +
		"does not count as secrets (URLs, IDs, file names, flags) out of the vault into plain\n" +
		"settings beside it. Values the scan counts as secrets, and names that look like one,\n" +
		"stay in the vault. Files keep working; nothing needs a restart.\n\n" +
		"Judging a value means reading it, so this asks for Touch ID once, --dry-run included.",
	Args: cobra.NoArgs,
	RunE: runMigrateSettings,
}

type migrateSettingsResult struct {
	// Read is how many entries were judged.
	Read int `json:"read"`
	// Moved are the entries moved out (with --dry-run, the ones that would be).
	Moved []string `json:"moved"`
	// Checks are entries kept in the vault because the name says secret.
	Checks []string `json:"checks"`
	// Skipped are settings-shaped entries left alone, each with why.
	Skipped []migrateSettingsSkip `json:"skipped"`
	DryRun  bool                  `json:"dry_run,omitempty"`
}

type migrateSettingsSkip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func runMigrateSettings(cmd *cobra.Command, _ []string) error {
	if err := validateOutputFormat(migrateSettingsFormat); err != nil {
		return fmt.Errorf("jit migrate settings: %w", err)
	}
	if migrateSettingsFormat == "json" && !migrateYes {
		return fmt.Errorf("jit migrate settings: --format json needs --yes; a confirmation cannot be answered on a JSON stream")
	}
	root, err := vaultRootDir()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	usage, err := collectVaultUsers(root, cwd)
	if err != nil {
		return fmt.Errorf("jit migrate settings: nothing moved, can't tell which profiles name what: %w", err)
	}

	// The candidates: every vault entry born from a .env, named by a profile
	// or not. Every one is read and its class recorded, so the Vault window's
	// "may hold settings" count reaches zero; only those a profile names, and
	// no pointer file does, can move. Info reads the header only, no Touch ID.
	// A 1Password link is never a candidate: reading it resolves the item,
	// and a plain copy would cut the link (the app does not count them).
	readVault := &vault.Vault{Root: root}
	stored, err := readVault.List()
	if err != nil {
		return fmt.Errorf("jit migrate settings: %w", err)
	}
	type candidate struct {
		settingMoveTarget
		why string // why it cannot move even if it is a setting; "" when it can
	}
	var candidates []candidate
	for _, p := range stored {
		if vault.IsBackupPath(p) {
			continue
		}
		info, err := readVault.Info(p)
		if err != nil || info.Class != vault.ClassDotenv || info.Storage == vault.StorageOpRef {
			continue
		}
		c := candidate{settingMoveTarget: settingMoveTarget{path: p, from: p, to: settings.Pointer(p)}}
		for _, u := range usage.byPath[p] {
			if u.PointerFile != "" {
				c.why = "a pointer file names it (" + shortPath(u.PointerFile) + ")"
			}
			if u.ProfilePath != "" && !containsString(c.manifests, u.ProfilePath) {
				c.manifests = append(c.manifests, u.ProfilePath)
				c.profiles = append(c.profiles, u.ProfileName)
			}
		}
		if c.why == "" && len(c.manifests) == 0 {
			c.why = "no profile names it"
		}
		candidates = append(candidates, c)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].path < candidates[j].path })

	w := cmd.OutOrStdout()
	result := migrateSettingsResult{Moved: []string{}, Checks: []string{}, Skipped: []migrateSettingsSkip{}, DryRun: migrateDryRun}
	if len(candidates) == 0 {
		if migrateSettingsFormat == "json" {
			return writeJSON(w, result)
		}
		fmt.Fprintln(w, "Nothing to check: no vault entry came from a protected .env.")
		return nil
	}
	if !migrateYes {
		q := fmt.Sprintf("Read %s from protected .env files and move the plain settings among them out of the vault? [y/N] ",
			countWord(len(candidates), "entry", "entries"))
		if migrateDryRun {
			q = fmt.Sprintf("Read %s from protected .env files to list the plain settings among them? Nothing moves. [y/N] ",
				countWord(len(candidates), "entry", "entries"))
		}
		if !confirmPrompt(cmd, q) {
			fmt.Fprintln(w, "Nothing read.")
			return nil
		}
	}

	v, err := openVaultFreshAuth()
	if err != nil {
		return fmt.Errorf("jit migrate settings: %w", err)
	}
	reason := fmt.Sprintf("check %s for settings to move out of the vault", countWord(len(candidates), "entry", "entries"))
	if err := requireFreshUserPresence(v, reason); err != nil {
		return fmt.Errorf("jit migrate settings: nothing moved: %w", err)
	}
	classes, cerr := settings.LoadClasses(root)
	if cerr != nil {
		classes = nil
	}
	store := settings.New(root)
	for _, c := range candidates {
		value, err := v.Get(c.path)
		if err != nil {
			result.Skipped = append(result.Skipped, migrateSettingsSkip{Path: c.path, Reason: "could not be read: " + err.Error()})
			continue
		}
		result.Read++
		class := audit.ClassifyEnvVar(path.Base(c.path), string(value))
		if classes != nil {
			classes.Set(c.path, string(class))
		}
		switch {
		case class == audit.EnvVarCheck:
			result.Checks = append(result.Checks, c.path)
			continue
		case class == audit.EnvVarSecret:
			continue
		case c.why != "":
			result.Skipped = append(result.Skipped, migrateSettingsSkip{Path: c.path, Reason: "a setting, left in the vault: " + c.why})
			continue
		case migrateDryRun:
			result.Moved = append(result.Moved, c.path)
			continue
		}
		if _, err := settingMoveOne(v, store, classes, c.settingMoveTarget, true); err != nil {
			return fmt.Errorf("jit migrate settings: %w (moved so far: %d)", err, len(result.Moved))
		}
		if classes != nil {
			classes.Set(c.path, "")
		}
		result.Moved = append(result.Moved, c.path)
	}
	// A dry run changes nothing, the class index included: a class recorded
	// here would tell the app these entries were checked, and hide the
	// cleanup that has not happened.
	if classes != nil && !migrateDryRun {
		_ = classes.Save()
	}

	if migrateSettingsFormat == "json" {
		return writeJSON(w, result)
	}
	verb := "Moved"
	if migrateDryRun {
		verb = "Would move"
	}
	_, _ = cBold.Fprintf(w, "%s %s out of the vault\n", verb, countWord(len(result.Moved), "setting", "settings"))
	for _, p := range result.Moved {
		fmt.Fprintf(w, "  %s %s\n", glyphBullet, p)
	}
	if len(result.Checks) > 0 {
		_, _ = cWarn.Fprintf(w, "  note: %s stayed in the vault because the name looks like a secret\n", countWord(len(result.Checks), "entry", "entries"))
		for _, p := range result.Checks {
			fmt.Fprintf(w, "    %s %s\n", glyphBullet, p)
		}
		wrapBody(w, 0, "  ", hlCmds("  to keep one plain anyway: `jit vault move-out <path>`"))
	}
	for _, s := range result.Skipped {
		fmt.Fprintf(w, "  %s %s: %s\n", glyphWarn, s.Path, s.Reason)
	}
	return nil
}

func init() {
	migrateSettingsCmd.Flags().StringVar(&migrateSettingsFormat, "format", "text", `output format: "text" (default) or "json"; json needs --yes`)
	migrateCmd.AddCommand(migrateSettingsCmd)
}
