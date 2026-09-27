// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
)

// jit migrate preview is the Protect sheet's question before Touch ID
// (design/secrets-only-vault.md): for each file, where each .env variable
// would go, and which MCP configs read a .env the same run protects. It
// reads files and classifies; it never opens the vault, so it never prompts.
// A value bound for the vault never appears, only a setting's.
var migratePreviewCmd = &cobra.Command{
	Use:   "preview <file>...",
	Short: "Show where each .env variable would go, before anything moves",
	Long: "Show, for each named .env, which variables would go to the vault and which would stay as\n" +
		"plain settings, and for each MCP config, the .env files it reads. Nothing is read from\n" +
		"the vault and nothing changes. Setting values are shown; secrets never are.",
	Args: cobra.MinimumNArgs(1),
	RunE: runMigratePreview,
}

type migratePreviewResult struct {
	Files []migratePreviewFile `json:"files"`
}

type migratePreviewFile struct {
	Path string `json:"path"`
	// Kind is "env", "mcp", or "other" (a file this preview does not split).
	Kind string              `json:"kind"`
	Vars []migratePreviewVar `json:"vars,omitempty"`
	MCP  *migratePreviewMCP  `json:"mcp,omitempty"`
}

type migratePreviewVar struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	InVault bool   `json:"in_vault"`
	Value   string `json:"value,omitempty"`
}

// migratePreviewMCP says what an MCP config would move. Covered is true when
// it holds nothing inline and every .env it reads is protected already or
// named in this same run: protecting it then moves nothing more.
type migratePreviewMCP struct {
	Reads   []string `json:"reads"`
	Inline  int      `json:"inline_servers"`
	Covered bool     `json:"covered"`
}

func runMigratePreview(cmd *cobra.Command, args []string) error {
	split, err := loadMigrateSplit()
	if err != nil {
		return fmt.Errorf("jit migrate preview: %w", err)
	}
	named := map[string]bool{}
	abs := make([]string, 0, len(args))
	for _, a := range args {
		p, err := filepath.Abs(a)
		if err != nil {
			return err
		}
		p = filepath.Clean(p)
		abs = append(abs, p)
		named[p] = true
	}
	result := migratePreviewResult{Files: make([]migratePreviewFile, 0, len(abs))}
	for _, p := range abs {
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("jit migrate preview: %w", err)
		}
		f := migratePreviewFile{Path: p, Kind: "other"}
		switch {
		case !info.Mode().IsRegular():
			// A live mount, or a folder: nothing this preview splits.
		case migrate.IsEnvFileName(filepath.Base(p)):
			plan, ok := migrate.EnvFileSplitPreview(p, split.forFile(p))
			if ok {
				f.Kind = "env"
				for _, vp := range plan {
					f.Vars = append(f.Vars, migratePreviewVar{Name: vp.Name, Class: string(vp.Class), InVault: vp.InVault, Value: vp.Value})
				}
			}
		default:
			reads := migrate.MCPEnvFilePreview(p)
			protected := migrate.ProtectedMCPEnvFiles(p)
			inline := migrate.MCPInlineServers(p)
			if len(reads) == 0 && len(protected) == 0 && inline == 0 {
				break
			}
			f.Kind = "mcp"
			all := append(append([]string{}, reads...), protected...)
			covered := inline == 0 && len(all) > 0
			for _, r := range reads {
				if !named[filepath.Clean(r)] {
					covered = false
				}
			}
			f.MCP = &migratePreviewMCP{Reads: all, Inline: inline, Covered: covered}
		}
		result.Files = append(result.Files, f)
	}
	if migrateFormat != "json" {
		return errors.New("jit migrate preview: only --format json is supported; jit migrate --dry-run <file> is the readable plan")
	}
	return writeJSON(cmd.OutOrStdout(), result)
}

func init() {
	migrateCmd.AddCommand(migratePreviewCmd)
	migratePreviewCmd.Flags().StringVar(&migrateFormat, "format", "text", `output format: "json" (required)`)
	migratePreviewCmd.Flags().StringArrayVar(&migrateSecretNames, "secret", nil, "as jit migrate's --secret")
	migratePreviewCmd.Flags().StringArrayVar(&migrateSettingNames, "setting", nil, "as jit migrate's --setting")
}
