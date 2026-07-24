// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/profile"
)

// completeProfileNames offers the profile names visible from the current
// directory — project-local first, then global, exactly the set `Load`
// resolves. Shared by every `--profile` flag (run/export/doctor/aws/k8s/
// sops), so a name the shell could never guess becomes tab-completable.
// Names are deduped (a project profile shadows a global one of the same
// name) and each carries its scope as the completion description.
func completeProfileNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	infos, err := profile.ListAll(cwd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	seen := map[string]bool{}
	var out []string
	for _, info := range infos {
		if seen[info.Name] || !strings.HasPrefix(info.Name, toComplete) {
			continue
		}
		seen[info.Name] = true
		out = append(out, fmt.Sprintf("%s\t%s", info.Name, info.Scope))
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
