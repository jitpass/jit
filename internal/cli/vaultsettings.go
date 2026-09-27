// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"os"
	"path"
	"slices"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/settings"
)

var vaultSettingsFormat string

// jit vault settings lists the plain settings kept beside the vault
// (design/secrets-only-vault.md), values included: they are as readable as
// the .env lines they came from, and reading them needs no Touch ID. It is
// what the Vault window's Settings section shows.
var vaultSettingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "List the plain settings kept beside the vault, with their values",
	Long: "List the plain settings jit keeps beside the vault: the lines of a protected .env the\n" +
		"scan does not count as secrets (URLs, IDs, file names, flags). They are plain text,\n" +
		"readable without Touch ID. jit vault move-in puts one in the vault.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateOutputFormat(vaultSettingsFormat); err != nil {
			return fmt.Errorf("jit vault settings: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return err
		}
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		store := settings.New(root)
		paths, err := store.List()
		if err != nil {
			return fmt.Errorf("jit vault settings: %w", err)
		}
		pointers := make([]string, len(paths))
		for i, p := range paths {
			pointers[i] = settings.Pointer(p)
		}
		refs := referencesForPaths(root, cwd, pointers)
		result := vaultSettingsResult{Settings: make([]vaultSettingJSON, 0, len(paths))}
		for i, p := range paths {
			value, err := store.Get(p)
			if err != nil {
				continue
			}
			var usedBy []string
			for _, r := range refs[pointers[i]] {
				if !slices.Contains(usedBy, r.ProfileName) {
					usedBy = append(usedBy, r.ProfileName)
				}
			}
			result.Settings = append(result.Settings, vaultSettingJSON{Path: p, Value: string(value), UsedBy: usedBy})
		}
		w := cmd.OutOrStdout()
		if vaultSettingsFormat == "json" {
			return writeJSON(w, result)
		}
		if len(result.Settings) == 0 {
			fmt.Fprintln(w, "No plain settings. Protecting a .env keeps its non-secret lines here.")
			return nil
		}
		group := ""
		for _, st := range result.Settings {
			if g := path.Dir(st.Path); g != group {
				group = g
				_, _ = cBold.Fprintf(w, "%s\n", group)
			}
			fmt.Fprintf(w, "  %s = %s\n", path.Base(st.Path), shorten1(st.Value, 60))
		}
		return nil
	},
}

type vaultSettingsResult struct {
	Settings []vaultSettingJSON `json:"settings"`
}

// vaultSettingJSON is one setting: its path, its value, and the profiles
// that name it. Omitted used_by means nothing names it any more.
type vaultSettingJSON struct {
	Path   string   `json:"path"`
	Value  string   `json:"value"`
	UsedBy []string `json:"used_by,omitempty"`
}

// shorten1 cuts a value to n runes for a listing line; the JSON keeps it
// whole.
func shorten1(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func init() {
	vaultSettingsCmd.Flags().StringVar(&vaultSettingsFormat, "format", "text", `output format: "text" (default) or "json"`)
	vaultCmd.AddCommand(vaultSettingsCmd)
}
