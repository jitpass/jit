// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/inject"
)

var (
	exportProfile string
	exportMode    string
)

var exportCmd = &cobra.Command{
	Use:     "export [--profile <name>] [--mode <mode>]",
	GroupID: groupSecrets,
	Short:   "Print shell export statements for a profile's secrets",
	Long: "jit export decrypts every secret a profile references and prints POSIX\n" +
		"shell `export VAR='value'` statements to stdout, meant to be evaluated\n" +
		"into the current session. Nothing is written to disk or to any shell init\n" +
		"file — the values live only in this one shell session's environment.\n\n" +
		"Profile selection works exactly like jit run's: without --profile, jit\n" +
		"resolves the project's migrated .env layers (looking upward from the\n" +
		"current directory) and exports their merged result in dotenv order —\n" +
		".env overridden by .env.local — announcing what it merged on stderr, so\n" +
		"eval never swallows it. --mode <m> layers .env.<m>/.env.<m>.local in;\n" +
		"--profile names one profile verbatim and disables merging.",
	Example: "  eval \"$(jit export)\"\n" +
		"  eval \"$(jit export --profile aws-admin)\"",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("jit export: %w", err)
		}
		// Announce on stderr: stdout must carry only the export lines,
		// which are meant to be eval'd.
		p, err := resolveInjectionProfile("jit export", cwd, exportProfile, exportMode, cmd.ErrOrStderr())
		if err != nil {
			return fmt.Errorf("jit export: %w", err)
		}

		v, err := openVault()
		if err != nil {
			return fmt.Errorf("jit export: %w", err)
		}
		values, err := inject.Resolve(v, p)
		if err != nil {
			return fmt.Errorf("jit export: %w", err)
		}

		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(cmd.OutOrStdout(), "export %s=%s\n", name, shellQuote(values[name]))
		}
		return nil
	},
}

// shellQuote wraps s in single quotes for POSIX shells (bash/zsh — the
// default on macOS), escaping any embedded single quote. Values are
// developer secrets, not something this CLI controls the shape of, so
// this has to be correct for arbitrary bytes, not just the common case.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func init() {
	exportCmd.Flags().StringVar(&exportProfile, "profile", "", "profile to export verbatim (default: merge this project's migrated .env layers)")
	exportCmd.Flags().StringVar(&exportMode, "mode", "", "also merge .env.<mode> and .env.<mode>.local layers (e.g. production)")
	rootCmd.AddCommand(exportCmd)
}
