// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/profile"
)

var (
	doctorProfile string
	doctorFormat  string
)

// doctorResult is jit doctor's --format json shape (GAPS.md #22) — Problems
// stays a flat list of the same human-readable strings the text path
// prints one-per-line, rather than a structured breakdown, since a script
// consuming this almost always just wants OK/not-OK plus the count, and
// restructuring every problem into fields (which profile, which variable,
// which failure kind) isn't worth the churn until something actually needs
// to filter on them programmatically.
type doctorResult struct {
	ProfilesChecked int      `json:"profiles_checked"`
	SecretsChecked  int      `json:"secrets_checked"`
	OK              bool     `json:"ok"`
	Problems        []string `json:"problems"`
}

var doctorCmd = &cobra.Command{
	Use:     "doctor",
	GroupID: groupWorkflow,
	Short:   "Verify every secret a profile references actually exists in the vault",
	Long: "jit doctor checks that every secret path a profile manifest references\n" +
		"actually exists in the vault — failing fast with a named missing secret\n" +
		"instead of letting an app crash later on an empty environment variable.\n" +
		"Only checks existence, never decrypts a value, so it never needs local\n" +
		"authentication.\n\n" +
		"By default checks every profile visible from the current directory: both\n" +
		"project-local ones under .jit/profiles/ and the home-rooted global ones\n" +
		"jit migrate writes for shell-config/MCP/AWS/kubeconfig/npmrc secrets —\n" +
		"the same set `jit profile list` shows. Use --profile to check just one.\n" +
		"--format json prints a machine-readable snapshot instead of the default\n" +
		"text report — still exits non-zero on any problem either way.",
	Args: cobra.NoArgs,
	// A "problems found" exit is a normal, expected outcome here, not a
	// usage mistake — cobra's default of dumping the usage string to
	// stdout on any RunE error would otherwise land right after (and
	// corrupt) a --format json snapshot on exactly the run a script most
	// needs to parse cleanly: the failing one.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(doctorFormat); err != nil {
			return fmt.Errorf("jit doctor: %w", err)
		}

		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("jit doctor: %w", err)
		}

		// targets is name+manifest pairs to check. The default (no
		// --profile) case must cover BOTH project-local profiles AND the
		// home-rooted global ones jit migrate writes for shell-config/
		// MCP/AWS/kubeconfig/npmrc (profile.ListAll) — a real, reported
		// bug: this used to call profile.ListNames(cwd), project-local
		// only, so a global-only profile was invisible to a bare `jit
		// doctor` even though `jit status`/`jit profile list` both
		// count it and status's own "run jit doctor for details" pointer
		// implied doctor would show the same problems it did. Loading via
		// LoadFile(info.Path) (not profile.Load(cwd, name)) also sidesteps
		// a subtler bug: if a project and a global profile ever share a
		// name, Load always resolves to the project one regardless of
		// which Info entry we're iterating, silently checking the same
		// file twice under two different scope labels.
		type target struct {
			name string
			path string // empty means "not yet resolved" (the --profile case, resolved via profile.Load itself below)
		}
		var targets []target
		if doctorProfile != "" {
			targets = []target{{name: doctorProfile}}
		} else {
			infos, err := profile.ListAll(cwd)
			if err != nil {
				return fmt.Errorf("jit doctor: %w", err)
			}
			for _, info := range infos {
				targets = append(targets, target{name: info.Name, path: info.Path})
			}
		}
		if len(targets) == 0 {
			if doctorFormat == "json" {
				return writeJSON(cmd.OutOrStdout(), doctorResult{OK: true, Problems: []string{}})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "No profiles found under %s/ or the global store — nothing to check.\n", profile.ProfilesDir)
			return nil
		}

		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit doctor: %w", err)
		}

		problems := []string{}
		checked := 0
		for _, t := range targets {
			var p profile.Profile
			var loadErr error
			if t.path != "" {
				p, loadErr = profile.LoadFile(t.path)
			} else {
				p, loadErr = profile.Load(cwd, t.name)
			}
			if loadErr != nil {
				problems = append(problems, fmt.Sprintf("[parse] %s", loadErr))
				continue
			}

			var vars []string
			for varName := range p {
				vars = append(vars, varName)
			}
			sort.Strings(vars)

			for _, varName := range vars {
				secretPath := p[varName]
				checked++
				exists, err := v.Exists(secretPath)
				if err != nil {
					problems = append(problems, fmt.Sprintf("[vault error] profile %q: checking %s (%s): %v", t.name, varName, secretPath, err))
					continue
				}
				if !exists {
					problems = append(problems, fmt.Sprintf(
						"[missing] profile %q: %s -> %s (not in the vault — run \"jit vault set %s\" to add it, or \"jit migrate home\" if it came from a scan)",
						t.name, varName, secretPath, secretPath))
				}
			}
		}

		if doctorFormat == "json" {
			if err := writeJSON(cmd.OutOrStdout(), doctorResult{
				ProfilesChecked: len(targets),
				SecretsChecked:  checked,
				OK:              len(problems) == 0,
				Problems:        problems,
			}); err != nil {
				return fmt.Errorf("jit doctor: %w", err)
			}
			if len(problems) > 0 {
				return fmt.Errorf("jit doctor: %d problem(s) found", len(problems))
			}
			return nil
		}

		if len(problems) > 0 {
			for _, p := range problems {
				_, _ = color.New(color.FgRed).Fprintf(cmd.OutOrStdout(), "✗ %s\n", p)
			}
			return fmt.Errorf("jit doctor: %d problem(s) found", len(problems))
		}

		_, _ = color.New(color.FgGreen, color.Bold).Fprintf(cmd.OutOrStdout(), "✓ %d profile(s), %d secret reference(s) all resolve cleanly\n", len(targets), checked)
		return nil
	},
}

func init() {
	doctorCmd.Flags().StringVar(&doctorProfile, "profile", "", "check only this profile instead of every profile under .jit/profiles/")
	doctorCmd.Flags().StringVar(&doctorFormat, "format", "text", `output format: "text" (default) or "json"`)
	rootCmd.AddCommand(doctorCmd)
}
