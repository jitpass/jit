// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// docs-gen regenerates docs/reference/commands/ from the command tree
// itself, so the published reference can't drift from `--help`: CI reruns
// it and fails on a dirty diff. Hidden — it's a maintainer tool, not part
// of the product surface, and hiding it also keeps it out of its own
// generated output.
//
// The markdown is rendered by hand (mirroring cobra/doc's page shape)
// rather than by importing github.com/spf13/cobra/doc: that package pulls
// go-md2man and a yaml module into the binary for man/yaml output we'd
// never use.
func init() {
	cmd := &cobra.Command{
		Use:     "docs-gen [dir]",
		Short:   "Regenerate the markdown command reference (run from the repo root)",
		Hidden:  true,
		GroupID: groupPlumbing, // invoked by CI, not by hand; hidden, so never rendered under the group anyway
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := filepath.Join("docs", "reference", "commands")
			if len(args) == 1 {
				dir = args[0]
			}
			if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- public docs tree in the repo, conventional mode
				return fmt.Errorf("jit docs-gen: %w", err)
			}
			// Clear previous output first so a renamed or removed command
			// doesn't leave an orphan page behind.
			entries, err := os.ReadDir(dir)
			if err != nil {
				return fmt.Errorf("jit docs-gen: %w", err)
			}
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".md") {
					if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
						return fmt.Errorf("jit docs-gen: %w", err)
					}
				}
			}
			if err := genCommandTree(dir, rootCmd); err != nil {
				return fmt.Errorf("jit docs-gen: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "regenerated %s\n", dir)
			return nil
		},
	}
	rootCmd.AddCommand(cmd)
}

// docsInclude mirrors rootUsageTemplate's visibility rule: every available
// command, plus commands hidden only from tab-completion (the plumbing
// commands, marked with helpVisibleAnnotation — see root.go). Plain hidden
// commands like docs-gen itself stay out.
func docsInclude(c *cobra.Command) bool {
	if c.IsAdditionalHelpTopicCommand() {
		return false
	}
	return c.IsAvailableCommand() || c.Annotations[helpVisibleAnnotation] != ""
}

func genCommandTree(dir string, cmd *cobra.Command) error {
	for _, c := range cmd.Commands() {
		if !docsInclude(c) {
			continue
		}
		if err := genCommandTree(dir, c); err != nil {
			return err
		}
	}
	page := renderCommandPage(cmd)
	return os.WriteFile(filepath.Join(dir, commandPageName(cmd)), []byte(page), 0o644) // #nosec G306 -- generated public docs page, conventional non-secret mode
}

// commandPageName is cobra/doc's naming scheme ("jit vault set" →
// jit_vault_set.md), kept so page URLs stay stable if the generator ever
// changes.
func commandPageName(cmd *cobra.Command) string {
	return strings.ReplaceAll(cmd.CommandPath(), " ", "_") + ".md"
}

func renderCommandPage(cmd *cobra.Command) string {
	var b strings.Builder
	b.WriteString("## " + cmd.CommandPath() + "\n\n")
	b.WriteString(cmd.Short + "\n\n")
	if cmd.Long != "" {
		b.WriteString("### Synopsis\n\n" + cmd.Long + "\n\n")
	}
	if cmd.Runnable() {
		b.WriteString("```\n" + cmd.UseLine() + "\n```\n\n")
	}
	if cmd.Example != "" {
		b.WriteString("### Examples\n\n```\n" + cmd.Example + "\n```\n\n")
	}
	if flags := cmd.NonInheritedFlags(); flags.HasAvailableFlags() {
		b.WriteString("### Options\n\n```\n" + flags.FlagUsages() + "```\n\n")
	}
	if flags := cmd.InheritedFlags(); flags.HasAvailableFlags() {
		b.WriteString("### Options inherited from parent commands\n\n```\n" + flags.FlagUsages() + "```\n\n")
	}

	var related []string
	if parent := cmd.Parent(); parent != nil {
		related = append(related, seeAlsoLine(parent))
	}
	for _, c := range cmd.Commands() {
		if !docsInclude(c) {
			continue
		}
		related = append(related, seeAlsoLine(c))
	}
	if len(related) > 0 {
		b.WriteString("### SEE ALSO\n\n")
		for _, line := range related {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func seeAlsoLine(cmd *cobra.Command) string {
	return "* [" + cmd.CommandPath() + "](" + commandPageName(cmd) + ")\t - " + cmd.Short + "\n"
}
