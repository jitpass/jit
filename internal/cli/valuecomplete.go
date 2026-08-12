// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// This file holds the completions for flags and positionals whose accepted
// values are a FIXED set jit already knows. Without them cobra falls through
// to file completion, so `jit audit --kind <TAB>` answered a closed
// vocabulary with a directory listing — worse than silence, because it reads
// as "this flag wants a path". Every list here is either derived from the
// validator that accepts it or pinned to it by a test in valuecomplete_test.go.

// completeValues offers a fixed set of values, each entry either "value" or
// "value\tdescription". Prefix filtering is done here rather than left to the
// shell, matching the rest of this package's completers.
func completeValues(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return filterValues(values, toComplete), cobra.ShellCompDirectiveNoFileComp
	}
}

// completeValuesWithHelp is completeValues plus an active-help line, for a
// value set that is a set of COMMON picks rather than the only accepted
// values — a duration or a date, where a bare list reads as exhaustive and
// closes off the free-form grammar (the report that produced
// completeGrantFor).
func completeValuesWithHelp(help string, values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		comps := cobra.AppendActiveHelp(filterValues(values, toComplete), help)
		return comps, cobra.ShellCompDirectiveNoFileComp
	}
}

// filterValues keeps the entries whose VALUE (the part before any tab-
// separated description) starts with what the user has typed.
func filterValues(values []string, toComplete string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		value := v
		if i := strings.IndexByte(v, '\t'); i >= 0 {
			value = v[:i]
		}
		if strings.HasPrefix(value, toComplete) {
			out = append(out, v)
		}
	}
	return out
}

// firstArgOnly restricts a value completion to the FIRST positional, for the
// commands that take at most one (`service ttl`, `service consent`). Past it
// there is nothing to offer, and cobra's fallback is file completion for a
// position the command would reject.
func firstArgOnly(fn func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return fn(cmd, args, toComplete)
	}
}

// completeOutputFormat is the completion for every --format flag that
// validateOutputFormat guards, built from the same slice so the two cannot
// disagree about what the flag takes.
func completeOutputFormat(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	desc := map[string]string{
		"text": "human-readable (default)",
		"json": "machine-readable",
	}
	values := make([]string, 0, len(outputFormats))
	for _, f := range outputFormats {
		values = append(values, f+"\t"+desc[f])
	}
	return filterValues(values, toComplete), cobra.ShellCompDirectiveNoFileComp
}

// completeCounts offers a few sensible values for a numeric flag. The point
// is not the numbers, it is that an int flag stops offering FILENAMES.
func completeCounts(values ...int) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strconv.Itoa(v))
	}
	return completeValues(out...)
}

// completeDurations offers common durations for a flag or positional that
// takes one, naming the ceiling in active help when there is one — a fixed
// list alone reads as the only accepted values.
func completeDurations(ceiling string, values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	help := "any duration works: 45m, 90m, 12h, ..."
	if ceiling != "" {
		help = fmt.Sprintf("any duration up to %s works: 45m, 90m, ...", ceiling)
	}
	return completeValuesWithHelp(help, values...)
}
