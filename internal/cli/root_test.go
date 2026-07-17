// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestEveryTopLevelCommandHasGroupID enforces the project rule that was
// previously review-time only: cobra does NOT error on a missing GroupID —
// the command silently lands under "Additional Commands" next to
// help/completion, undoing the grouped root help this package sets up.
// Cobra's own built-in help/completion commands are the two deliberate
// exceptions (they may or may not be registered yet depending on whether
// an earlier test ran Execute).
func TestEveryTopLevelCommandHasGroupID(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		if c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		if c.GroupID == "" {
			t.Errorf("top-level command %q has no GroupID, set one of the group constants in root.go", c.Name())
		}
	}
}

// TestNoInternalTrackerReferencesInHelpText enforces the other project
// rule this file's grouped-help pass introduced: never reference
// GAPS.md/RFC.md (or internal mechanism vocabulary like "Pillar") in
// Short/Long/Example — a Homebrew user has neither file, and "(GAPS.md
// #20)" in a help line reads as a changelog talking to itself. Checks
// every command recursively, so a new subcommand can't reintroduce one.
func TestNoInternalTrackerReferencesInHelpText(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, text := range []string{c.Short, c.Long, c.Example} {
			for _, marker := range []string{"GAPS.md", "RFC.md", "Pillar"} {
				if strings.Contains(text, marker) {
					t.Errorf("%q help text references internal tracker/vocabulary %q, say what the user observes instead:\n%s", c.CommandPath(), marker, text)
				}
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}
