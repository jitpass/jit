// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"os"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
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
		"gcp":  {migrate.GCPADCPath(home)},
		"sops": migrate.SOPSAgeKeyPaths(home),
		"npm":  {migrate.GlobalNpmrcPath(home)},
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
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return nil, fmt.Errorf("reading mount registry: %w", err)
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
			return nil, fmt.Errorf("--with %s: no migrated %s mount found (run `jit migrate home --only %s` first)", name, name, name)
		}
		out = append(out, matched)
	}
	return out, nil
}

func knownWithNames(kinds map[string][]string) string {
	names := make([]string, 0, len(kinds))
	for n := range kinds {
		names = append(names, n)
	}
	// small fixed set; sort for a stable error message
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
