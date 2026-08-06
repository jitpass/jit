// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
)

// This file resolves `jit run --with <name>` into a global, file-delivered
// mount to grant for the run (docs/internal/GLOBAL-MOUNT-GRANTS-PLAN.md §7).
// These are machine-wide credentials a tool reads from a fixed file path,
// with no call-out hook (gcp ADC) or which jit mounts for compatibility
// (global sops keys, global ~/.npmrc). Granting one always takes EXPLICIT
// user intent — the --with flag typed by the user, never a project-local
// file — because a global credential must not be reachable by an untrusted
// repo config (§2's invariant).

// globalMountKinds maps a --with name to the candidate on-disk paths of its
// global mount. The registry match below picks whichever candidate was
// actually migrated (sops has two possible locations; env overrides like
// $GOOGLE_APPLICATION_CREDENTIALS change nothing here, since the registry
// records the path migrate created). This table is the one place a new
// global file-delivered mount is registered.
func globalMountKinds(home string) map[string][]string {
	return map[string][]string{
		"gcp":   {migrate.GCPADCPath(home)},
		"sops":  migrate.SOPSAgeKeyPaths(home),
		"npm":   {migrate.GlobalNpmrcPath(home)},
		"netrc": {migrate.NetrcPath(home)},
		"pypi":  {migrate.PypircPath(home)},
	}
}

// withMountPaths resolves each --with name to its migrated global mount
// path. A name jit doesn't recognize, or one whose mount isn't migrated, is
// a hard error naming what to do — a --with the user typed must never fail
// silently (unlike the best-effort project-mount grants). The returned
// paths are ready to send to the agent in grant mode.
func withMountPaths(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	entries, home, err := loadMountRegistry()
	if err != nil {
		return nil, err
	}
	registered := make(map[string]bool, len(entries))
	for _, e := range entries {
		registered[e.MountPath] = true
	}

	kinds := globalMountKinds(home)
	var out []string
	for _, name := range names {
		candidates, known := kinds[name]
		if !known {
			return nil, fmt.Errorf("--with %s: unknown mount, expected one of %s", name, knownWithNames(kinds))
		}
		matched := ""
		for _, p := range candidates {
			if registered[p] {
				matched = p
				break
			}
		}
		if matched == "" {
			return nil, fmt.Errorf("--with %s: no migrated %s mount found (migrate the %s file first by naming it, e.g. `jit migrate <path-to-%s-file>`)", name, name, name, name)
		}
		out = append(out, matched)
	}
	return out, nil
}

// completeGlobalMountNames offers the global file-delivered mount names
// (gcp, sops, npm, netrc) for the `--with` flag (jit run) and the
// `--grant` flag (jit wrap add). It reads the names straight from
// globalMountKinds so the completion can never drift from the one table
// that defines what those flags accept.
func completeGlobalMountNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for name := range globalMountKinds(home) {
		if strings.HasPrefix(name, toComplete) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, cobra.ShellCompDirectiveNoFileComp
}

func knownWithNames(kinds map[string][]string) string {
	names := make([]string, 0, len(kinds))
	for n := range kinds {
		names = append(names, n)
	}
	sort.Strings(names) // small fixed set; sort for a stable error message
	return strings.Join(names, ", ")
}

// globalMountGuidance describes how to USE a migrated global file-delivered
// mount: the --with name that grants it and the tools that read it. It is the
// single source for the "how do I use this?" reminder shown at both
// discoverability moments (the jit migrate summary and jit doctor), per the
// global-mount-grants plan §12a.
type globalMountGuidance struct {
	name  string // the --with name (gcp, sops, npm, netrc)
	tools string // human list of the tools that read the mounted file
}

// usageLine is the one-line reminder both migrate and doctor print.
func (g globalMountGuidance) usageLine() string {
	return fmt.Sprintf("%s (%s): jit run --with %s <command>", g.name, g.tools, g.name)
}

// globalMountGuidanceForPath maps a registered mount path back to its usage
// guidance, or false if the path isn't a known global file-delivered mount.
func globalMountGuidanceForPath(home, mountPath string) (globalMountGuidance, bool) {
	switch mountPath {
	case migrate.GCPADCPath(home):
		return globalMountGuidance{name: "gcp", tools: "gcloud, terraform, Google SDKs"}, true
	case migrate.GlobalNpmrcPath(home):
		return globalMountGuidance{name: "npm", tools: "npm, yarn, pnpm"}, true
	case migrate.NetrcPath(home):
		return globalMountGuidance{name: "netrc", tools: "curl, git, ftp, wget"}, true
	case migrate.PypircPath(home):
		return globalMountGuidance{name: "pypi", tools: "twine, uv publish, poetry publish"}, true
	}
	for _, p := range migrate.SOPSAgeKeyPaths(home) {
		if mountPath == p {
			return globalMountGuidance{name: "sops", tools: "sops, kluctl"}, true
		}
	}
	return globalMountGuidance{}, false
}

// printGlobalMountReminders lists every migrated global file-delivered mount
// with its one-line `jit run --with` reminder — the discoverability half of
// the feature, so the `--with` usage stays findable long after the migrate
// summary scrolled off (plan §12a). Best-effort and silent when there are
// none or the registry can't be read: it is guidance, never a doctor problem.
func printGlobalMountReminders(w io.Writer) {
	entries, home, err := loadMountRegistry()
	if err != nil {
		return
	}
	var lines []string
	for _, e := range entries {
		if g, ok := globalMountGuidanceForPath(home, e.MountPath); ok {
			lines = append(lines, "  "+glyphBullet+" "+g.usageLine())
		}
	}
	if len(lines) == 0 {
		return
	}
	sort.Strings(lines)
	fmt.Fprintln(w, "\nGlobal credential mounts (granted only by an explicit --with, never by project config):")
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

// globalMountPaths is the set of every candidate on-disk path that is a
// machine-global file-delivered mount (the gcp ADC, sops age keys, the global
// ~/.npmrc). Project-scope logic (projectTemplateMounts) EXCLUDES these: a
// global credential is granted only by an explicit --with, never because a
// run's cwd happened to walk into the directory the credential lives in —
// which for gcp (~/.config/gcloud) and sops (~/.config/sops/age,
// ~/Library/Application Support/sops/age) is a $HOME SUBDIRECTORY, not $HOME
// itself, so a "parent == $HOME" test alone would miss them.
func globalMountPaths(home string) map[string]bool {
	set := map[string]bool{}
	for _, candidates := range globalMountKinds(home) {
		for _, p := range candidates {
			set[p] = true
		}
	}
	return set
}
